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

//! `polar-sign projection test`: a deployment's own mapping held to the checks a kind's own is (`polar-http-testkit`),
//! and a signed record of what was found (docs/architecture/http-observers.md, "Evidence", bite 4). The checks: the
//! mapping is inside the schema the agent's scaffold gives; signed as a runtime section and read back as the agent
//! reads its file, it is the same projection; and each sample beside it becomes what is written beside that.
//!
//! The record says what it is true of, by digest: the mapping's file and its body (what the schedules hold), the
//! scaffold (and the agent version it carries), each sample and what is written beside it, and this tool's version; the
//! reads of the mapping no sample reached, by the mapping's own names (`Projection::reads`); and the result, in lines that
//! name a sample and never say what it holds. It is signed in its own domain (`Domain::EVIDENCE_RECORD`), so it is never taken as a
//! configuration document, and goes in the evidence repository on Polar's git server, one file per record, named by
//! its digest, so a record is only ever added.

use crate::scaffold::Scaffold;
use crate::{Identity, projection_for, runtime_payload, sign_to_dhall, verify_source};
use polar_projection::Stamp;
use polar_projection::samples::{self, plainly};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

/// What a record of this kind says it is.
pub const PROJECTION_TEST: &str = "projection-test";

/// A deployment's mapping, the scaffold of the agent it is for, and the samples beside it.
pub struct ProjectionTest<'a> {
    /// The scaffold as it was read (`<agent> --scaffold`).
    pub scaffold: &'a str,
    pub section: &'a str,
    /// The mapping's file, as the author wrote it, and what to call it in the record.
    pub mapping: &'a str,
    pub mapping_name: &'a str,
    pub samples: &'a Path,
}

/// What a test found: the record to sign, and each problem said whole, for the person who ran it.
pub struct Tested {
    pub agent: String,
    /// What the record says, unsigned.
    pub record: Value,
    /// Each problem said whole, with what a sample became and what is beside it.
    pub details: Vec<String>,
}

impl Tested {
    pub fn passed(&self) -> bool {
        self.record["result"]["passed"] == json!(true)
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The stamp a sample is read with. The stamps are left out of what a sample becomes, so these only need to be some.
const STAMP: Stamp<'static> = Stamp {
    workload: "polar-sign",
    version: 1,
    observed_at_unix_secs: 0,
};

/// Runs the checks. `identity` signs the mapping for the round trip, which is not kept, and `trust_pem` is what the
/// signed file must verify against, as the agent's own CA. An error is a test that could not be run (the scaffold is
/// not one); anything about the mapping or its samples is in the record.
pub fn projection_test(
    test: &ProjectionTest<'_>,
    identity: &Identity,
    trust_pem: &[String],
    now: i64,
) -> Result<Tested, String> {
    let scaffold = Scaffold::parse(test.scaffold)?;
    let agent_version = serde_json::from_str::<Value>(test.scaffold)
        .ok()
        .and_then(|v| v.pointer("/agent/version").cloned())
        .unwrap_or(Value::Null);
    let mut brief: Vec<String> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    let mut problem = |line: String, whole: String| {
        brief.push(line);
        details.push(whole);
    };

    let read = samples::read(test.samples);
    let listed: Vec<Value> = match &read {
        Ok(found) => found
            .iter()
            .map(|sample| {
                json!({
                    "name": sample.name,
                    "document_sha256": sha256(&sample.document),
                    "expected_sha256": sample.expected.as_ref().map(|e| {
                        sha256(&polar_signing::canonical::encode(e).unwrap_or_default())
                    }),
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    };

    let mut body_sha256 = Value::Null;
    let mut coverage = Value::Null;
    match projection_for(&scaffold, test.section, test.mapping) {
        Err(problems) => {
            for p in problems {
                problem(
                    format!("the mapping is not one {} takes: {p}", scaffold.agent),
                    format!("the mapping is not one {} takes: {p}", scaffold.agent),
                );
            }
        }
        Ok(body) => {
            let projection = scaffold
                .projection(&body)
                .expect("judged by projection_for");
            // What the schedules hold is the body, not the author's file, so a check finds a test by this.
            body_sha256 = json!(sha256(
                &polar_signing::canonical::encode(&body).unwrap_or_default()
            ));
            // Signed as it would be, and read back as the agent reads the committed file.
            let payload = runtime_payload(
                &scaffold.agent,
                test.section,
                1,
                PROJECTION_TEST,
                body.clone(),
            );
            let back = sign_to_dhall(payload, identity)
                .and_then(|file| verify_source(&file, trust_pem, now));
            match back {
                Err(e) => problem(
                    format!("the mapping, signed, does not read back: {e}"),
                    format!("the mapping, signed, does not read back: {e}"),
                ),
                Ok((_, payload)) => {
                    let taken = scaffold.projection(&payload["body"]);
                    if payload["body"] != body || taken.as_ref() != Ok(&projection) {
                        problem(
                            "the mapping, signed and read back, is not the projection written"
                                .into(),
                            format!(
                                "the mapping, signed and read back, is not the projection written: {:?}",
                                taken.err()
                            ),
                        );
                    }
                }
            }
            match &read {
                Err(e) => problem(e.clone(), e.clone()),
                Ok(found) => {
                    let mut reached = std::collections::BTreeSet::new();
                    for sample in found {
                        let got = plainly(&sample.outcome(&projection, &STAMP));
                        if let Err(differs) = sample.check(&got) {
                            problem(differs.briefly(sample), differs.fully(sample));
                        }
                        if let Ok(document) = serde_json::from_slice::<Value>(&sample.document) {
                            reached.extend(projection.reached(&sample.name, &document));
                        }
                    }
                    let reads = projection.reads();
                    let unreached: Vec<&String> = reads.difference(&reached).collect();
                    coverage = json!({ "reads": reads.len(), "unreached": unreached });
                }
            }
        }
    }

    let record = json!({
        "type": PROJECTION_TEST,
        "subject": { "agent": scaffold.agent, "section": test.section },
        "mapping": {
            "file": test.mapping_name,
            "sha256": sha256(test.mapping.as_bytes()),
            "body_sha256": body_sha256,
        },
        "coverage": coverage,
        "scaffold": { "sha256": sha256(test.scaffold.as_bytes()), "agent_version": agent_version },
        "samples": listed,
        "tool": polar_version::record("polar-sign"),
        "result": { "passed": brief.is_empty(), "problems": brief },
        "tested_at_unix_secs": now,
    });
    Ok(Tested {
        agent: scaffold.agent,
        record,
        details,
    })
}

/// Writes what each sample becomes now beside it, as what it is expected to become, and names them. To be read before they
/// are committed, since they are then what the mapping is held to. Nothing is written if the mapping is not one the agent
/// takes.
pub fn bless(
    scaffold: &Scaffold,
    section: &str,
    mapping: &str,
    samples: &Path,
) -> Result<Vec<String>, Vec<String>> {
    let body = projection_for(scaffold, section, mapping)?;
    let projection = scaffold.projection(&body)?;
    let found = samples::read(samples).map_err(|e| vec![e])?;
    let mut written = Vec::new();
    for sample in &found {
        sample
            .bless(&plainly(&sample.outcome(&projection, &STAMP)))
            .map_err(|e| vec![e])?;
        written.push(sample.expected_at.display().to_string());
    }
    Ok(written)
}

/// A record signed by `identity` in the evidence domain, as the JSON that is committed.
pub fn sign_record(record: Value, identity: &Identity) -> Result<String, String> {
    let document = polar_signing::sign_in(
        polar_signing::Domain::EVIDENCE_RECORD,
        record,
        &identity.chain,
        &identity.key_pem,
    )
    .map_err(|e| format!("cannot sign the record: {e}"))?;
    serde_json::to_string_pretty(&document.to_value())
        .map(|text| format!("{text}\n"))
        .map_err(|e| e.to_string())
}

/// Checks a signed evidence record as anything that reads one must: in the evidence domain, chaining to `trust_pem`.
/// Who signed it, and what it says.
pub fn verify_record(
    text: &str,
    trust_pem: &[String],
    now: i64,
) -> Result<(polar_signing::SignerInfo, Value), String> {
    let value: Value =
        serde_json::from_str(text).map_err(|e| format!("the record is not JSON: {e}"))?;
    let document = polar_signing::Document::from_value(&value).map_err(|e| e.to_string())?;
    let trust = polar_signing::Trust::from_pem(trust_pem).map_err(|e| e.to_string())?;
    let signer = polar_signing::verify_in(
        polar_signing::Domain::EVIDENCE_RECORD,
        &document,
        &trust,
        now,
    )
    .map_err(|e| e.to_string())?;
    Ok((signer, document.payload))
}

/// Where a signed record goes in the evidence repository: under its kind, agent and section, named by its own digest,
/// so no two records share a place and none is ever replaced.
pub fn place(agent: &str, section: &str, signed: &str) -> String {
    format!(
        "{PROJECTION_TEST}/{agent}/{section}/{}.json",
        sha256(signed.as_bytes())
    )
}

/// The commit message for a record.
pub fn message(agent: &str, section: &str, tested: &Tested, signer: &str) -> String {
    let samples = tested.record["samples"].as_array().map_or(0, Vec::len);
    format!(
        "test({agent}): the {section} mapping {} its {samples} sample(s)\n\nMapping sha256 {}. Signed by {signer} with polar-sign.",
        if tested.passed() { "passes" } else { "fails" },
        tested.record["mapping"]["sha256"].as_str().unwrap_or("?")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_signing::testing::{Spec, now, root, signer};
    use std::path::PathBuf;

    const EXAMPLE: &str = include_str!("../../polar-projection/examples/openapi.dhall");

    fn examples() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../polar-projection/examples/openapi")
    }

    /// What `openapi-processor --scaffold` says of its graph and its one section, with an agent version.
    fn scaffold(edges: Value) -> String {
        json!({
            "agent": {"name": "openapi-processor", "version": {"name": "openapi-processor", "version": "9.9.9"}},
            "runtime": [{"name": "projection", "doc": "d", "body": {}}],
            "graph": [
                {"label": "OpenApiApplication", "access": "owns", "purpose": "p", "keys": [["source"]]},
                {"label": "OpenApiEndpoint", "access": "owns", "purpose": "p", "keys": [["source", "method", "path"]]}
            ],
            "graph_edges": edges
        })
        .to_string()
    }

    fn has_endpoint() -> Value {
        json!([{"from": "OpenApiApplication", "kind": "HAS_ENDPOINT", "to": "OpenApiEndpoint", "purpose": "p"}])
    }

    struct Signer {
        identity: Identity,
        trust: Vec<String>,
    }

    fn someone() -> Signer {
        let ca = root("Polar Internal CA");
        let s = signer(&ca, Spec::default());
        Signer {
            identity: Identity {
                chain: vec![s.cert_pem],
                key_pem: s.key_pem,
            },
            trust: vec![ca.pem],
        }
    }

    fn run(scaffold_text: &str, samples: &Path, who: &Signer) -> Tested {
        projection_test(
            &ProjectionTest {
                scaffold: scaffold_text,
                section: "projection",
                mapping: EXAMPLE,
                mapping_name: "openapi.dhall",
                samples,
            },
            &who.identity,
            &who.trust,
            now(),
        )
        .unwrap()
    }

    #[test]
    fn the_example_passes_and_its_record_names_what_it_is_true_of() {
        let who = someone();
        let text = scaffold(has_endpoint());
        let tested = run(&text, &examples(), &who);
        assert!(tested.passed(), "{:#?}", tested.details);
        assert!(tested.details.is_empty());
        assert_eq!(tested.agent, "openapi-processor");
        let record = &tested.record;
        assert_eq!(record["type"], PROJECTION_TEST);
        assert_eq!(
            record["subject"],
            json!({ "agent": "openapi-processor", "section": "projection" })
        );
        assert_eq!(record["mapping"]["file"], "openapi.dhall");
        assert_eq!(record["mapping"]["sha256"], sha256(EXAMPLE.as_bytes()));
        assert_eq!(record["scaffold"]["sha256"], sha256(text.as_bytes()));
        assert_eq!(record["scaffold"]["agent_version"]["version"], "9.9.9");
        assert_eq!(record["tool"]["name"], "polar-sign");
        assert_eq!(record["tool"]["version"], polar_version::PLATFORM);
        assert_eq!(record["tested_at_unix_secs"], now());
        assert_eq!(record["result"], json!({ "passed": true, "problems": [] }));
        assert_eq!(record["coverage"], json!({ "reads": 20, "unreached": [] }));
        let body = crate::projection_body(EXAMPLE).unwrap();
        assert_eq!(
            record["mapping"]["body_sha256"],
            sha256(&polar_signing::canonical::encode(&body).unwrap())
        );
        let listed = record["samples"].as_array().unwrap();
        let found = samples::read(&examples()).unwrap();
        assert_eq!(listed.len(), found.len());
        for (entry, sample) in listed.iter().zip(&found) {
            assert_eq!(entry["name"], sample.name);
            assert_eq!(entry["document_sha256"], sha256(&sample.document));
            let canonical =
                polar_signing::canonical::encode(sample.expected.as_ref().unwrap()).unwrap();
            assert_eq!(entry["expected_sha256"], sha256(&canonical));
        }
    }

    #[test]
    fn a_sample_that_becomes_something_else_fails_and_the_record_says_which_and_not_what() {
        let who = someone();
        let dir = tempfile::tempdir().unwrap();
        for entry in std::fs::read_dir(examples()).unwrap() {
            let path = entry.unwrap().path();
            std::fs::copy(&path, dir.path().join(path.file_name().unwrap())).unwrap();
        }
        let changed = dir.path().join("openapi-3.0.expected.json");
        let mut expected: Value =
            serde_json::from_str(&std::fs::read_to_string(&changed).unwrap()).unwrap();
        expected["skipped"] = json!(1);
        std::fs::write(&changed, expected.to_string()).unwrap();
        std::fs::remove_file(dir.path().join("swagger-2.0.expected.json")).unwrap();

        let tested = run(&scaffold(has_endpoint()), dir.path(), &who);
        assert!(!tested.passed());
        let problems: Vec<&str> = tested.record["result"]["problems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(
            problems[0].contains("`openapi-3.0` became other than"),
            "{problems:?}"
        );
        assert!(
            problems[1].contains("`swagger-2.0` has nothing beside it"),
            "{problems:?}"
        );
        for p in &problems {
            assert!(
                !p.contains("Orders"),
                "a line says nothing a sample holds: {p}"
            );
        }
        assert!(
            tested.details[0].contains("Orders"),
            "said whole to the person running it"
        );
        let swagger = tested.record["samples"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "swagger-2.0")
            .unwrap();
        assert_eq!(swagger["expected_sha256"], Value::Null);
    }

    #[test]
    fn a_mapping_outside_the_agent_s_schema_fails_and_says_why() {
        let who = someone();
        let tested = run(&scaffold(json!([])), &examples(), &who);
        assert!(!tested.passed());
        let problems = tested.record["result"]["problems"].as_array().unwrap();
        assert!(
            problems.iter().all(|p| p
                .as_str()
                .unwrap()
                .starts_with("the mapping is not one openapi-processor takes")),
            "{problems:?}"
        );
        assert!(!problems.is_empty());
        // What was given is still named.
        assert_eq!(tested.record["samples"].as_array().unwrap().len(), 5);
        assert_eq!(tested.record["mapping"]["body_sha256"], Value::Null);
        assert_eq!(tested.record["coverage"], Value::Null);
    }

    #[test]
    fn the_reads_no_sample_reaches_are_named_by_the_mapping() {
        let who = someone();
        let dir = tempfile::tempdir().unwrap();
        for name in ["no-paths.json", "no-paths.expected.json"] {
            std::fs::copy(examples().join(name), dir.path().join(name)).unwrap();
        }
        let tested = run(&scaffold(has_endpoint()), dir.path(), &who);
        assert!(tested.passed(), "it is evidence, not a failure");
        let unreached: Vec<&str> = tested.record["coverage"]["unreached"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        for name in [
            "endpoint each body.paths",
            "endpoint.method from method",
            "application.swagger from body.swagger",
        ] {
            assert!(unreached.contains(&name), "{name} in {unreached:?}");
        }
        assert!(!unreached.contains(&"application.title from body.info.title"));
        assert_eq!(tested.record["coverage"]["reads"], 20);
    }

    #[test]
    fn a_mapping_with_no_samples_fails() {
        let who = someone();
        let dir = tempfile::tempdir().unwrap();
        let tested = run(&scaffold(has_endpoint()), dir.path(), &who);
        assert!(!tested.passed());
        assert!(
            tested.record["result"]["problems"][0]
                .as_str()
                .unwrap()
                .contains("no samples")
        );
    }

    #[test]
    fn a_signer_the_ca_does_not_know_fails_the_round_trip() {
        let who = someone();
        let other = someone();
        let tested = projection_test(
            &ProjectionTest {
                scaffold: &scaffold(has_endpoint()),
                section: "projection",
                mapping: EXAMPLE,
                mapping_name: "openapi.dhall",
                samples: &examples(),
            },
            &who.identity,
            &other.trust,
            now(),
        )
        .unwrap();
        assert!(!tested.passed());
        assert!(
            tested.record["result"]["problems"][0]
                .as_str()
                .unwrap()
                .starts_with("the mapping, signed, does not read back")
        );
    }

    #[test]
    fn a_scaffold_that_is_not_one_is_no_test() {
        let who = someone();
        let result = projection_test(
            &ProjectionTest {
                scaffold: "{}",
                section: "projection",
                mapping: EXAMPLE,
                mapping_name: "m",
                samples: &examples(),
            },
            &who.identity,
            &who.trust,
            now(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_signed_record_verifies_as_evidence_and_as_nothing_else_and_not_once_changed() {
        let who = someone();
        let tested = run(&scaffold(has_endpoint()), &examples(), &who);
        let signed = sign_record(tested.record.clone(), &who.identity).unwrap();
        let (_, said) = verify_record(&signed, &who.trust, now()).unwrap();
        assert_eq!(said, tested.record);

        // Not a configuration document.
        let document =
            polar_signing::Document::from_value(&serde_json::from_str(&signed).unwrap()).unwrap();
        assert!(
            polar_signing::verify(
                &document,
                &polar_signing::Trust::from_pem(&who.trust).unwrap(),
                now()
            )
            .is_err()
        );
        // Nor a record once changed.
        let mut changed: Value = serde_json::from_str(&signed).unwrap();
        changed["payload"]["result"]["passed"] = json!(false);
        assert!(verify_record(&changed.to_string(), &who.trust, now()).is_err());
        // Nor one signed under a CA it is not checked against.
        assert!(verify_record(&signed, &someone().trust, now()).is_err());
    }

    #[test]
    fn blessed_samples_are_then_what_the_test_holds_the_mapping_to() {
        let who = someone();
        let dir = tempfile::tempdir().unwrap();
        for entry in std::fs::read_dir(examples()).unwrap() {
            let path = entry.unwrap().path();
            if !path.to_string_lossy().ends_with(".expected.json") {
                std::fs::copy(&path, dir.path().join(path.file_name().unwrap())).unwrap();
            }
        }
        assert!(!run(&scaffold(has_endpoint()), dir.path(), &who).passed());
        let text = scaffold(has_endpoint());
        let parsed = Scaffold::parse(&text).unwrap();
        let written = bless(&parsed, "projection", EXAMPLE, dir.path()).unwrap();
        assert_eq!(written.len(), 5);
        assert!(run(&text, dir.path(), &who).passed());
        for name in ["no-paths", "openapi-3.1"] {
            let read = |d: &Path| -> Value {
                serde_json::from_str(
                    &std::fs::read_to_string(d.join(format!("{name}.expected.json"))).unwrap(),
                )
                .unwrap()
            };
            assert_eq!(read(dir.path()), read(&examples()), "{name}");
        }
        // Nothing is written for a mapping the agent does not take.
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("s.json"), "{}").unwrap();
        let outside = Scaffold::parse(&scaffold(json!([]))).unwrap();
        assert!(bless(&outside, "projection", EXAMPLE, other.path()).is_err());
        assert!(!other.path().join("s.expected.json").exists());
    }

    #[test]
    fn each_record_has_a_place_of_its_own() {
        let a = place("openapi-processor", "projection", "one");
        let b = place("openapi-processor", "projection", "two");
        assert!(a.starts_with("projection-test/openapi-processor/projection/"));
        assert!(a.ends_with(".json"));
        assert_ne!(a, b);
        assert_eq!(a, place("openapi-processor", "projection", "one"));
    }
}
