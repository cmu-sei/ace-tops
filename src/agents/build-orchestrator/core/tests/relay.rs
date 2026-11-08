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

//! The relay (src/relay.rs): what the orchestrator does with a report the reader read, before it goes to Cassini.

use orchestrator_core::relay::{NotRelayed, Relay, RelayBounds, is_digest};
use orchestrator_report::{Bounds, Report, Tape, gate, parse};
use polar::events::{BuildReport, ProvenanceEvent};
use proptest::prelude::*;

const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// What the reader makes of `line`.
fn read(line: &str) -> Report {
    let bounds = Bounds::default();
    gate(line.as_bytes(), &bounds).unwrap();
    let mut tape = Tape::new(&bounds);
    parse(line.as_bytes(), &bounds, &mut tape).unwrap();
    Report::read(line.as_bytes(), &tape).unwrap()
}

fn relay() -> Relay {
    Relay::new("ours", RelayBounds::default())
}

#[test]
fn a_report_is_relayed_as_the_orchestrators_build_whatever_build_id_the_line_says() {
    let line = r#"{"type": "stage_started", "build_id": "theirs", "stage_name": "build", "stage_id": "s1", "at": "t"}"#;
    let relayed = relay().relay(read(line)).unwrap();
    assert_eq!(relayed.build_id, "ours");
    match relayed.report {
        ProvenanceEvent::StageStarted {
            build_id,
            stage_name,
            ..
        } => {
            assert_eq!((build_id.as_str(), stage_name.as_str()), ("ours", "build"))
        }
        other => panic!("{other:?}"),
    }
    let artifact = format!(
        r#"{{"type": "artifact_produced", "build_id": "theirs", "artifact_content_hash": "{DIGEST}", "artifact_type": "binary"}}"#
    );
    match relay().relay(read(&artifact)).unwrap().report {
        ProvenanceEvent::ArtifactProduced(p) => assert_eq!(p.build_id.as_deref(), Some("ours")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_hash_that_is_not_a_sha256_digest_is_refused_naming_its_field() {
    for (line, field) in [
        (r#"{"type": "artifact_produced", "artifact_content_hash": "abc", "artifact_type": "binary"}"#.to_string(), "artifact_content_hash"),
        (format!(r#"{{"type": "binary_linked", "binary_content_hash": "{DIGEST}", "binary_name": "b", "root_purl": "pkg:cargo/b@1", "sbom_content_hash": "sha256:ABC"}}"#), "sbom_content_hash"),
        (format!(r#"{{"type": "container_image_created", "image_name": "i", "tarball_hash": "{DIGEST}", "config_digest": "{DIGEST}", "layers": [{{"order": 0, "diff_id": "sha256:{}"}}]}}"#, "0".repeat(63)), "diff_id"),
        (format!(r#"{{"type": "container_image_created", "image_name": "i", "tarball_hash": "{DIGEST}", "config_digest": "{DIGEST}", "layers": [], "digest": "latest"}}"#), "digest"),
    ] {
        assert_eq!(relay().relay(read(&line)).map(|_| ()), Err(NotRelayed::NotADigest(field)), "{line}");
    }
    assert!(is_digest(DIGEST));
    for not in [
        "",
        "sha256:",
        "sha512:00",
        "SHA256:0123",
        &DIGEST.to_uppercase(),
        &format!("{DIGEST}0"),
    ] {
        assert!(!is_digest(not), "{not}");
    }
}

#[test]
fn a_build_reports_no_more_lines_or_bytes_than_its_bounds_and_its_refusals_are_counted() {
    let mut r = Relay::new(
        "ours",
        RelayBounds {
            reports: 3,
            bytes: 100,
        },
    );
    assert!(r.take(10).is_ok() && r.take(10).is_ok() && r.take(10).is_ok());
    assert_eq!(r.take(10), Err(NotRelayed::TooMany(3)));
    let mut r = Relay::new(
        "ours",
        RelayBounds {
            reports: 100,
            bytes: 100,
        },
    );
    assert!(r.take(60).is_ok());
    assert_eq!(r.take(41), Err(NotRelayed::TooMuch(100)));
    assert!(r.take(40).is_ok(), "a line within what is left is taken");
    r.refuse();
    assert_eq!(r.refused(), 2);
}

fn digest() -> impl Strategy<Value = String> {
    "[0-9a-f]{64}".prop_map(|hex| format!("sha256:{hex}"))
}

/// A report of each kind that holds a hash, its hashes well-formed.
fn hashed() -> impl Strategy<Value = Report> {
    prop_oneof![
        (digest(), "\\PC{0,8}").prop_map(|(h, t)| Report::ArtifactProduced {
            artifact_content_hash: h,
            artifact_type: t.clone(),
            name: t,
            content_type: String::new(),
        }),
        (digest(), digest(), digest()).prop_map(|(a, b, c)| Report::BinaryLinked {
            binary_content_hash: a,
            binary_name: "b".into(),
            root_purl: "pkg:cargo/b@1".into(),
            sbom_content_hash: b,
            binding_digest: c,
        }),
        (
            digest(),
            digest(),
            proptest::collection::vec(digest(), 0..4),
            proptest::option::of(digest())
        )
            .prop_map(|(tarball, config, diffs, image)| {
                Report::ContainerImageCreated(orchestrator_report::ContainerImageCreated {
                    image_name: "i".into(),
                    tarball_hash: tarball,
                    config_digest: config,
                    layers: diffs
                        .into_iter()
                        .enumerate()
                        .map(|(i, d)| orchestrator_report::Layer {
                            order: i as u32,
                            diff_id: d,
                            tar_path: String::new(),
                        })
                        .collect(),
                    digest: image.unwrap_or_default(),
                    ..Default::default()
                })
            }),
    ]
}

proptest! {
    /// A report whose hashes are sha256 digests is relayed, and the envelope reads back from its wire encoding as itself.
    #[test]
    fn a_well_formed_report_is_relayed_and_its_envelope_survives_the_wire(report in hashed()) {
        let relayed = relay().relay(report).unwrap();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&relayed).unwrap();
        let back = rkyv::from_bytes::<BuildReport, rkyv::rancor::Error>(&bytes).unwrap();
        prop_assert_eq!(format!("{back:?}"), format!("{relayed:?}"));
        prop_assert_eq!(back.build_id, "ours");
    }

    /// Any one of its hashes made not a digest, by a character or by length, and it is refused.
    #[test]
    fn a_report_with_any_hash_spoiled_is_refused(report in hashed(), how in 0usize..3) {
        let spoil = |h: &mut String| match how {
            0 => h.push('0'),
            1 => { h.pop(); }
            _ => *h = h.to_uppercase(),
        };
        let mut report = report;
        match &mut report {
            Report::ArtifactProduced { artifact_content_hash, .. } => spoil(artifact_content_hash),
            Report::BinaryLinked { sbom_content_hash, .. } => spoil(sbom_content_hash),
            Report::ContainerImageCreated(c) => spoil(&mut c.config_digest),
            _ => unreachable!(),
        }
        prop_assert!(matches!(relay().relay(report), Err(NotRelayed::NotADigest(_))));
    }
}
