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

//! A report's grammar: what each kind a build may report must and may hold, checked over the tape, and a checked line
//! decoded into owned values.

use orchestrator_report::*;
use proptest::prelude::*;

/// What `line` reads as: through the gate, the parser and the check, then decoded.
fn read(line: &str) -> Result<Report, Refusal> {
    let bounds = Bounds::default();
    gate(line.as_bytes(), &bounds)?;
    let mut tape = Tape::new(&bounds);
    parse(line.as_bytes(), &bounds, &mut tape)?;
    Report::read(line.as_bytes(), &tape)
}

#[test]
fn each_kind_a_build_may_report_is_read_and_its_build_id_never_believed() {
    let started = r#"{"type": "stage_started", "build_id": "not-this-one", "stage_name": "build", "stage_id": "s1", "at": "2026-11-08T00:00:00Z"}"#;
    assert_eq!(
        read(started),
        Ok(Report::StageStarted {
            stage_name: "build".into(),
            stage_id: "s1".into(),
            at: "2026-11-08T00:00:00Z".into()
        })
    );
    let artifact = r#"{"type": "artifact_produced", "artifact_content_hash": "sha256:00", "artifact_type": "binary"}"#;
    assert_eq!(
        read(artifact),
        Ok(Report::ArtifactProduced {
            artifact_content_hash: "sha256:00".into(),
            artifact_type: "binary".into(),
            name: String::new(),
            content_type: String::new(),
        }),
        "a field with a default may be left out"
    );
}

#[test]
fn what_a_report_may_not_hold_is_refused() {
    for (line, why) in [
        (r#"[1]"#, Refusal::NotAnObject),
        (r#"{"stage_name": "x"}"#, Refusal::UnknownKind),
        (
            r#"{"type": "execution_started", "build_id": "b"}"#,
            Refusal::UnknownKind,
        ),
        (
            r#"{"type": "execution_failed", "build_id": "b", "reason": "r"}"#,
            Refusal::UnknownKind,
        ),
        (r#"{"type": 1}"#, Refusal::WrongType),
        (
            r#"{"type": "stage_started", "stage_name": "a", "stage_id": "b", "at": "c", "extra": 1}"#,
            Refusal::UnknownKey,
        ),
        (
            r#"{"type": "stage_started", "stage_name": "a", "at": "c"}"#,
            Refusal::MissingKey,
        ),
        (
            r#"{"type": "stage_started", "stage_name": 1, "stage_id": "b", "at": "c"}"#,
            Refusal::WrongType,
        ),
        (
            r#"{"type": "stage_completed", "stage_name": "a", "stage_id": "b", "duration_secs": 1, "outcome": "won", "at": "c"}"#,
            Refusal::UnknownWord,
        ),
        (
            r#"{"type": "artifact_produced", "artifact_content_hash": "h", "artifact_type": "t", "name": null}"#,
            Refusal::WrongType,
        ),
        (
            r#"{"type": "sbom_analyzed", "artifact_content_hash": "h", "filename": "f", "components": [{"name": "n", "version": "v", "component_type": "c"}], "edges": []}"#,
            Refusal::MissingKey,
        ),
        (
            r#"{"type": "container_image_created", "image_name": "i", "tarball_hash": "t", "config_digest": "c", "layers": [{"order": 4294967296, "diff_id": "d"}]}"#,
            Refusal::NumberTooLarge,
        ),
    ] {
        assert_eq!(read(line), Err(why), "{line}");
    }
}

/// The fuzzer's seeds (`fuzz/seeds`), one of each kind as the pipeline writes it, are reports, so that fuzzing starts from
/// every kind.
#[test]
fn every_fuzz_seed_is_a_report_and_together_they_are_every_kind() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
    let mut kinds = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let line = std::fs::read_to_string(&path).unwrap();
        let report = read(&line).unwrap_or_else(|why| panic!("{}: {why}", path.display()));
        kinds.push(std::mem::discriminant(&report));
    }
    kinds.sort_by_key(|k| format!("{k:?}"));
    kinds.dedup();
    assert_eq!(kinds.len(), 8, "a seed of each kind");
}

#[test]
fn a_tape_that_is_not_the_lines_is_refused_never_read_past() {
    let line = r#"{"type": "stage_started", "stage_name": "a", "stage_id": "b", "at": "c"}"#;
    let bounds = Bounds::default();
    let mut tape = Tape::new(&bounds);
    parse(line.as_bytes(), &bounds, &mut tape).unwrap();
    let short = &line.as_bytes()[..10];
    assert!(check(short, &tape).is_err(), "spans past the text");
    tape.tokens[0] = Token::Object {
        members: 4,
        end: 1000,
    };
    assert!(
        check(line.as_bytes(), &tape).is_err(),
        "an end past the tape"
    );
    tape.tokens[0] = Token::Object { members: 4, end: 0 };
    assert!(
        check(line.as_bytes(), &tape).is_err(),
        "an end before itself"
    );
}

fn text() -> impl Strategy<Value = String> {
    prop_oneof!["\\PC{0,16}", "[\"\\\\\n\r\t\u{1}\u{7f}é😀a/]{0,8}"]
}

fn maybe() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(text())
}

fn package() -> impl Strategy<Value = PackageRef> {
    (text(), text(), text(), text(), maybe(), maybe()).prop_map(
        |(purl, name, version, component_type, license, source)| PackageRef {
            purl,
            name,
            version,
            component_type,
            license,
            source,
        },
    )
}

fn report() -> impl Strategy<Value = Report> {
    let outcome = prop_oneof![
        Just(StageOutcome::Succeeded),
        Just(StageOutcome::Failed),
        Just(StageOutcome::Skipped),
        Just(StageOutcome::Cancelled)
    ];
    prop_oneof![
        (text(), text(), text()).prop_map(|(stage_name, stage_id, at)| Report::StageStarted {
            stage_name,
            stage_id,
            at
        }),
        (text(), text(), any::<u64>(), outcome, text()).prop_map(
            |(stage_name, stage_id, duration_secs, outcome, at)| {
                Report::StageCompleted {
                    stage_name,
                    stage_id,
                    duration_secs,
                    outcome,
                    at,
                }
            }
        ),
        (text(), text(), proptest::collection::vec(maybe(), 9)).prop_map(
            |(severity, identifier, m)| {
                Report::SecurityAdvisoryFound(SecurityAdvisoryFound {
                    severity,
                    identifier,
                    in_artifact: m[0].clone(),
                    kind: m[1].clone(),
                    scanner: m[2].clone(),
                    affected_package: m[3].clone(),
                    cve_id: m[4].clone(),
                    ghsa_id: m[5].clone(),
                    fix_version: m[6].clone(),
                    unaffected_constraint: m[7].clone(),
                    advisory_url: m[8].clone(),
                })
            }
        ),
        (
            proptest::collection::vec(text(), 4),
            proptest::collection::vec(maybe(), 4)
        )
            .prop_map(|(t, m)| {
                Report::PackageStatusFound(PackageStatusFound {
                    kind: t[0].clone(),
                    identifier: t[1].clone(),
                    package_name: t[2].clone(),
                    package_version: t[3].clone(),
                    in_artifact: m[0].clone(),
                    affected_package: m[1].clone(),
                    advisory_url: m[2].clone(),
                    scanner: m[3].clone(),
                })
            }),
        proptest::collection::vec(text(), 4).prop_map(|t| Report::ArtifactProduced {
            artifact_content_hash: t[0].clone(),
            artifact_type: t[1].clone(),
            name: t[2].clone(),
            content_type: t[3].clone(),
        }),
        (
            text(),
            text(),
            proptest::option::of(package()),
            proptest::collection::vec(package(), 0..4),
            proptest::collection::vec((text(), proptest::collection::vec(text(), 0..4)), 0..4),
        )
            .prop_map(
                |(artifact_content_hash, filename, root, components, edges)| {
                    Report::SbomAnalyzed(SbomAnalyzed {
                        artifact_content_hash,
                        filename,
                        root,
                        components,
                        edges: edges
                            .into_iter()
                            .map(|(from_ref, to_refs)| DependencyEdge { from_ref, to_refs })
                            .collect(),
                    })
                }
            ),
        proptest::collection::vec(text(), 5).prop_map(|t| Report::BinaryLinked {
            binary_content_hash: t[0].clone(),
            binary_name: t[1].clone(),
            root_purl: t[2].clone(),
            sbom_content_hash: t[3].clone(),
            binding_digest: t[4].clone(),
        }),
        (
            proptest::collection::vec(text(), 10),
            proptest::collection::vec((any::<u32>(), text(), text()), 0..4),
            proptest::collection::vec(text(), 0..4),
        )
            .prop_map(|(t, layers, repo_tags)| {
                Report::ContainerImageCreated(ContainerImageCreated {
                    image_name: t[0].clone(),
                    tarball_hash: t[1].clone(),
                    config_digest: t[2].clone(),
                    layers: layers
                        .into_iter()
                        .map(|(order, diff_id, tar_path)| Layer {
                            order,
                            diff_id,
                            tar_path,
                        })
                        .collect(),
                    os: t[3].clone(),
                    arch: t[4].clone(),
                    created: t[5].clone(),
                    entrypoint: t[6].clone(),
                    cmd: t[7].clone(),
                    repo_tags,
                    digest: t[8].clone(),
                    uri: t[9].clone(),
                })
            }),
    ]
}

/// The written report with one field its kind must have renamed to one it does not have (`zz_` before its name). The first
/// `"name"` in the line is the key: inside a value every quote is escaped, so a name there ends `\"`, never `"`.
fn without_first_required(line: &str, report: &Report) -> Option<String> {
    let required = match report {
        Report::StageStarted { .. } => "\"stage_name\"",
        Report::StageCompleted { .. } => "\"duration_secs\"",
        Report::SecurityAdvisoryFound(_) => "\"severity\"",
        Report::PackageStatusFound(_) => "\"package_version\"",
        Report::ArtifactProduced { .. } => "\"artifact_type\"",
        Report::SbomAnalyzed(_) => "\"components\"",
        Report::BinaryLinked { .. } => "\"root_purl\"",
        Report::ContainerImageCreated(_) => "\"layers\"",
    };
    line.find(required)
        .map(|at| format!("{}\"zz_{}", &line[..at], &line[at + 1..]))
}

proptest! {
    /// Any report, with any text in its fields, written as the pipeline writes it, reads back as itself.
    #[test]
    fn a_report_reads_back_as_itself(r in report()) {
        let line = r.line();
        prop_assert_eq!(read(&line), Ok(r), "{}", line);
    }

    /// A report with one field it must have renamed is refused, whatever the rest of it holds.
    #[test]
    fn a_report_without_a_field_it_must_have_is_refused(r in report()) {
        let line = r.line();
        if let Some(changed) = without_first_required(&line, &r) {
            prop_assert!(read(&changed).is_err(), "{}", changed);
        }
    }
}
