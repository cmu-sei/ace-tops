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

//! Each invariant over a sound fact base, the sandbox's real model with the OpenAPI pair's mapping signed and tested,
//! and over that fact base made wrong in the one way the invariant is about.

use super::*;
use crate::evidence::{ProjectionTest, projection_test};
use polar_signing::testing::{Spec, now, root, signer};
use proptest::prelude::*;
use std::path::PathBuf;
use std::sync::OnceLock;

const MODEL: &str =
    include_str!("../../../credentials-agent/model/tests/fixtures/sandbox-model.json");
const MAPPING: &str = include_str!("../../../polar-projection/examples/openapi.dhall");
const PROCESSOR: &str = "openapi-processor";

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}

fn canonical_sha256(value: &Value) -> String {
    sha256(&polar_signing::canonical::encode(value).unwrap())
}

/// What `openapi-processor --scaffold` says of its graph and its one section.
fn processor_scaffold(edges: Value) -> String {
    json!({
        "agent": {"name": PROCESSOR, "version": {"name": PROCESSOR, "version": "9.9.9"}},
        "runtime": [{"name": "projection", "doc": "d", "body": serde_json::from_str::<Value>(
            r#"{"rules": {"type": "a projection: polar-projection/projection.dhall, signed with polar-sign runtime --projection", "required": true}}"#
        ).unwrap()}],
        "graph": [
            {"label": "OpenApiApplication", "access": "owns", "purpose": "p", "keys": [["source"]]},
            {"label": "OpenApiEndpoint", "access": "owns", "purpose": "p", "keys": [["source", "method", "path"]]},
            {"label": "Pod", "access": "reads", "purpose": "p"}
        ],
        "graph_edges": edges
    })
    .to_string()
}

fn has_endpoint() -> Value {
    json!([{"from": "OpenApiApplication", "kind": "HAS_ENDPOINT", "to": "OpenApiEndpoint", "purpose": "p"}])
}

fn other_scaffold(workload: &str, owns: &[&str]) -> ScaffoldFact {
    let graph: Vec<Value> = owns
        .iter()
        .map(|l| json!({"label": l, "access": "owns", "purpose": "p", "keys": [["id"]]}))
        .collect();
    let document = json!({"agent": {"name": workload}, "runtime": [], "graph": graph});
    ScaffoldFact {
        sha256: sha256(document.to_string().as_bytes()),
        document,
    }
}

fn section(agent: &str, name: &str, version: u64, body: Value) -> Section {
    Section {
        agent: agent.into(),
        name: name.into(),
        id: format!("{agent}-{name}"),
        version,
        body_sha256: canonical_sha256(&body),
        body,
        signer: "alice".into(),
        file: format!("permanent/{agent}/{name}.dhall"),
        versions: polar_version::VersionRange::default(),
        migrations: vec![],
    }
}

/// The record a projection test of the example makes, by the processor's scaffold, run once.
fn tested() -> &'static Value {
    static RECORD: OnceLock<Value> = OnceLock::new();
    RECORD.get_or_init(|| {
        let ca = root("Polar Internal CA");
        let s = signer(&ca, Spec::default());
        let identity = crate::Identity {
            chain: vec![s.cert_pem],
            key_pem: s.key_pem,
        };
        let samples =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../polar-projection/examples/openapi");
        projection_test(
            &ProjectionTest {
                scaffold: &processor_scaffold(has_endpoint()),
                section: "projection",
                mapping: MAPPING,
                mapping_name: "openapi.dhall",
                samples: &samples,
            },
            &identity,
            &[ca.pem],
            now(),
        )
        .unwrap()
        .record
    })
}

fn evidence(record: Value, file: &str) -> Evidence {
    Evidence {
        file: file.into(),
        signer: "alice".into(),
        record,
    }
}

/// The sandbox's model, every deployed workload's scaffold the check needs, and what a sound deployment signs: the
/// mapping, tested; the state agent's schema and agents list as the render seeds them.
fn base() -> FactBase {
    let model = Model::parse(MODEL).unwrap();
    let processor = processor_scaffold(has_endpoint());
    let mut scaffolds = BTreeMap::new();
    scaffolds.insert(
        PROCESSOR.to_string(),
        ScaffoldFact {
            sha256: sha256(processor.as_bytes()),
            document: serde_json::from_str(&processor).unwrap(),
        },
    );
    scaffolds.insert(
        "soft-state-observer".to_string(),
        other_scaffold("soft-state-observer", &[]),
    );
    scaffolds.insert(
        "soft-state-processor".to_string(),
        other_scaffold("soft-state-processor", &["AgentHealth"]),
    );
    let schema = json!({ "workloads": [
        { "workload": PROCESSOR, "identity": "openapi-processor.polar.serviceaccount.cluster.local",
          "owns": ["OpenApiApplication", "OpenApiEndpoint"], "reads": ["Pod"] },
        { "workload": "soft-state-processor", "identity": "soft-state-processor.polar.serviceaccount.cluster.local",
          "owns": ["AgentHealth"], "reads": [] },
    ]});
    let agents: Vec<Value> = model
        .workloads
        .iter()
        .filter(|w| w.kind.as_deref() == Some("agent") && w.config.as_deref() == Some("document"))
        .map(|w| json!({ "workload": w.workload, "identity": w.identity }))
        .collect();
    let mapping = crate::projection_body(MAPPING).unwrap();
    FactBase {
        instance: Instance {
            target: "sandbox-local".into(),
            ca_sha256: "ca".into(),
        },
        model,
        deployed: vec![],
        scaffolds,
        sections: vec![
            section(PROCESSOR, "projection", 3, mapping),
            section("soft-state-observer", "schema", 1, schema),
            section(
                "soft-state-processor",
                "agents",
                1,
                json!({ "workloads": agents }),
            ),
        ],
        evidence: vec![evidence(
            tested().clone(),
            "projection-test/openapi-processor/projection/a.json",
        )],
        inputs: BTreeMap::new(),
        settings: vec![],
        running: None,
        applied: vec![],
        migration_files: BTreeMap::new(),
    }
}

fn verdict_of<'a>(checked: &'a Checked, id: &str) -> &'a Verdict {
    checked.verdicts.iter().find(|v| v.id == id).unwrap()
}

fn status(facts: &FactBase, id: &str) -> (Status, Vec<String>) {
    let checked = check(facts);
    let v = verdict_of(&checked, id);
    (v.status, v.witness.clone())
}

fn a_line(witness: &[String], says: &str) -> bool {
    witness.iter().any(|l| l.contains(says))
}

#[test]
fn a_sound_deployment_holds_every_invariant_each_with_what_holds_it() {
    let checked = check(&base());
    for v in &checked.verdicts {
        assert_eq!(v.status, Status::Holds, "{}: {:#?}", v.id, v.witness);
        assert!(!v.witness.is_empty());
    }
    assert!(checked.holds());
    let pairs = verdict_of(&checked, "pairs-connected");
    assert!(a_line(
        &pairs.witness,
        "openapi-observer -> openapi-processor on `polar.openapi.observations`"
    ));
    let tested = verdict_of(&checked, "projections-tested");
    assert!(a_line(
        &tested.witness,
        "openapi-processor projection version 3: tested by alice"
    ));
}

#[test]
fn the_ids_are_stable_and_each_said_once() {
    let ids: Vec<&str> = check(&base()).verdicts.iter().map(|v| v.id).collect();
    assert_eq!(
        ids,
        [
            "pairs-connected",
            "authority-reaches-every-agent",
            "one-owner-per-label",
            "projections-inside-schema",
            "projections-tested",
            "certified-by-the-credentials-agent",
            "seen-by-health",
            "sections-in-range",
            "migrations-applied",
        ]
    );
}

fn with_policy(source: &str) -> FactBase {
    let mut facts = base();
    facts.sections.push(section(
        CREDENTIALS_AGENT,
        "policy",
        1,
        json!({ "source": source }),
    ));
    facts
}

#[test]
fn a_policy_that_cuts_a_pair_violates_pairs_connected_and_names_the_side() {
    let facts = with_policy(
        r#"forbid (principal == Identity::"openapi-processor.polar.serviceaccount.cluster.local", action == Action::"subscribe", resource == Topic::"polar.openapi.observations");"#,
    );
    let (got, witness) = status(&facts, "pairs-connected");
    assert_eq!(got, Status::Violated);
    assert_eq!(
        witness,
        [
            "openapi-observer publishes `polar.openapi.observations` and openapi-processor hears it, but openapi-processor may not hear it"
        ]
    );
    let unreadable = with_policy("this is not cedar");
    assert_eq!(status(&unreadable, "pairs-connected").0, Status::Violated);
}

#[test]
fn a_policy_that_cuts_renewal_violates_authority_reaching_every_agent() {
    let facts = with_policy(
        r#"forbid (principal == Identity::"credentials-agent-observer.polar.serviceaccount.cluster.local", action == Action::"publish", resource == Topic::"credentials-workload-issuance-requests");"#,
    );
    let (got, witness) = status(&facts, "authority-reaches-every-agent");
    assert_eq!(got, Status::Violated, "{witness:#?}");
}

#[test]
fn two_owners_of_a_label_or_a_schema_that_disagrees_violates_one_owner_per_label() {
    let mut two = base();
    two.scaffolds.insert(
        "jira-processor".into(),
        other_scaffold("jira-processor", &["OpenApiApplication"]),
    );
    let (got, witness) = status(&two, "one-owner-per-label");
    assert_eq!(got, Status::Violated);
    assert_eq!(
        witness,
        ["OpenApiApplication is owned by jira-processor, openapi-processor"]
    );

    let mut disagrees = base();
    let schema = disagrees
        .sections
        .iter_mut()
        .find(|s| s.name == "schema")
        .unwrap();
    schema.body["workloads"][0]["owns"] = json!(["OpenApiApplication"]);
    let (got, witness) = status(&disagrees, "one-owner-per-label");
    assert_eq!(got, Status::Violated);
    assert!(a_line(
        &witness,
        "OpenApiEndpoint is owned by openapi-processor and the state agent's schema names no owner"
    ));

    let mut another = base();
    let schema = another
        .sections
        .iter_mut()
        .find(|s| s.name == "schema")
        .unwrap();
    schema.body["workloads"][1]["owns"] = json!(["AgentHealth", "OpenApiApplication"]);
    schema.body["workloads"][0]["owns"] = json!(["OpenApiEndpoint"]);
    let (got, witness) = status(&another, "one-owner-per-label");
    assert_eq!(got, Status::Violated);
    assert_eq!(
        witness,
        [
            "OpenApiApplication is owned by openapi-processor by its scaffold and by soft-state-processor in the state agent's schema"
        ]
    );

    let mut none = base();
    none.sections.retain(|s| s.name != "schema");
    assert_eq!(
        status(&none, "one-owner-per-label").1,
        ["the state agent has no schema signed"]
    );

    // A scaffold of a workload this deployment does not run owns nothing here.
    let mut elsewhere = base();
    elsewhere.scaffolds.insert(
        "not-deployed".into(),
        other_scaffold("not-deployed", &["OpenApiApplication"]),
    );
    assert_eq!(status(&elsewhere, "one-owner-per-label").0, Status::Holds);
}

#[test]
fn a_projection_outside_its_scaffold_or_with_none_violates_projections_inside_schema() {
    let mut outside = base();
    let narrower = processor_scaffold(json!([]));
    outside.scaffolds.insert(
        PROCESSOR.into(),
        ScaffoldFact {
            sha256: sha256(narrower.as_bytes()),
            document: serde_json::from_str(&narrower).unwrap(),
        },
    );
    let (got, witness) = status(&outside, "projections-inside-schema");
    assert_eq!(got, Status::Violated);
    assert!(
        a_line(&witness, "openapi-processor projection version 3:"),
        "{witness:#?}"
    );

    let mut unjudged = base();
    unjudged
        .sections
        .push(section("jira-observer", "credentials", 1, json!({})));
    let (got, witness) = status(&unjudged, "projections-inside-schema");
    assert_eq!(got, Status::Violated);
    assert_eq!(
        witness,
        ["jira-observer has its credentials section signed and no scaffold to judge it by"]
    );
}

/// A section is a projection only when its agent's scaffold says its `rules` are one: other rules are not judged as one.
#[test]
fn only_a_section_its_scaffold_says_holds_a_projection_is_judged_as_one() {
    let mut facts = base();
    let observer = json!({
        "agent": {"name": "openapi-observer"},
        "runtime": [{"name": "filters", "doc": "d", "body": {"rules": {"type": "a list of filter rules", "required": true}}}],
        "graph": []
    });
    facts.scaffolds.insert(
        "openapi-observer".into(),
        ScaffoldFact {
            sha256: sha256(observer.to_string().as_bytes()),
            document: observer,
        },
    );
    facts.sections.push(section(
        "openapi-observer",
        "filters",
        1,
        json!({ "rules": [] }),
    ));
    let checked = check(&facts);
    for id in ["projections-inside-schema", "projections-tested"] {
        let v = verdict_of(&checked, id);
        assert_eq!(v.status, Status::Holds, "{id}: {:#?}", v.witness);
        assert!(
            !a_line(&v.witness, "openapi-observer"),
            "{id}: {:#?}",
            v.witness
        );
    }
}

#[test]
fn a_projection_not_tested_at_the_version_in_force_is_violated_or_no_longer_covered() {
    let mut never = base();
    never.evidence.clear();
    assert_eq!(
        status(&never, "projections-tested"),
        (
            Status::Violated,
            vec!["openapi-processor projection version 3: never tested".to_string()]
        )
    );

    let mut other_body = base();
    other_body.evidence[0].record["mapping"]["body_sha256"] = json!("another");
    assert_eq!(
        status(&other_body, "projections-tested").0,
        Status::NoLongerCovered
    );

    let mut other_scaffold = base();
    other_scaffold.evidence[0].record["scaffold"]["sha256"] = json!("another");
    assert_eq!(
        status(&other_scaffold, "projections-tested").0,
        Status::NoLongerCovered
    );

    let mut failed = base();
    failed.evidence[0].record["result"]["passed"] = json!(false);
    assert_eq!(
        status(&failed, "projections-tested").1,
        ["openapi-processor projection version 3: its test at this version failed"]
    );

    let mut uncovered = base();
    uncovered.evidence[0].record["coverage"]["unreached"] = json!(["endpoint each body.paths"]);
    let (got, witness) = status(&uncovered, "projections-tested");
    assert_eq!(got, Status::Violated);
    assert!(a_line(
        &witness,
        "no sample reaches endpoint each body.paths"
    ));

    // A newer version signed after the test is no longer covered by it.
    let mut newer = base();
    let mut body = crate::projection_body(MAPPING).unwrap();
    body["rules"][0]["set"] = json!([]);
    newer
        .sections
        .push(section(PROCESSOR, "projection", 4, body));
    let (got, witness) = status(&newer, "projections-tested");
    assert_eq!(got, Status::NoLongerCovered, "{witness:#?}");
    assert!(a_line(&witness, "version 4"));
}

#[test]
fn a_workload_issued_by_cert_issuer_that_is_not_a_bootstrap_service_violates_certification() {
    let mut facts = base();
    let w = facts
        .model
        .workloads
        .iter_mut()
        .find(|w| w.workload == "kube-observer")
        .unwrap();
    w.issuer = "cert-issuer".into();
    assert_eq!(
        status(&facts, "certified-by-the-credentials-agent"),
        (
            Status::Violated,
            vec!["kube-observer is issued by cert-issuer".to_string()]
        )
    );
}

#[test]
fn an_agent_left_out_of_the_agents_list_or_a_stranger_in_it_violates_seen_by_health() {
    let mut missing = base();
    let agents = missing
        .sections
        .iter_mut()
        .find(|s| s.name == "agents")
        .unwrap();
    agents.body["workloads"]
        .as_array_mut()
        .unwrap()
        .retain(|w| w["workload"] != "openapi-processor");
    let (got, witness) = status(&missing, "seen-by-health");
    assert_eq!(got, Status::Violated);
    assert_eq!(
        witness,
        [
            "openapi-processor (openapi-processor.polar.serviceaccount.cluster.local) is not in the agents list, so its health is not asked"
        ]
    );

    let mut stranger = base();
    let agents = stranger
        .sections
        .iter_mut()
        .find(|s| s.name == "agents")
        .unwrap();
    agents.body["workloads"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "workload": "cert-issuer", "identity": "cert-issuer.polar.serviceaccount.cluster.local" }));
    assert!(a_line(
        &status(&stranger, "seen-by-health").1,
        "cert-issuer.polar.serviceaccount.cluster.local is in the agents list"
    ));

    let mut old = base();
    old.model.workloads[0].kind = None;
    assert!(a_line(&status(&old, "seen-by-health").1, "render again"));

    let mut unsigned = base();
    unsigned.sections.retain(|s| s.name != "agents");
    assert_eq!(
        status(&unsigned, "seen-by-health").1,
        ["the state agent's writer has no agents list signed"]
    );
}

#[test]
fn the_report_says_what_each_workload_could_touch() {
    let mut facts = base();
    facts.sections.push(section(
        "openapi-observer",
        "sources",
        1,
        json!({ "sources": [{ "name": "a", "url": "https://petstore.example.org/openapi.json" }] }),
    ));
    let reach = check(&facts).reach;
    assert_eq!(
        reach["openapi-observer"]["hosts"],
        json!(["petstore.example.org"])
    );
    assert!(
        reach["openapi-observer"]["publishes"]
            .as_array()
            .unwrap()
            .contains(&json!("polar.openapi.observations"))
    );
    assert_eq!(
        reach[PROCESSOR]["owns"],
        json!(["OpenApiApplication", "OpenApiEndpoint"])
    );
    assert_eq!(reach[PROCESSOR]["reads"], json!(["Pod"]));
}

#[test]
fn the_record_is_the_common_envelope_with_each_verdict_by_its_id() {
    let facts = with_policy("this is not cedar");
    let checked = check(&facts);
    let record = record(&facts, &checked, 7);
    assert_eq!(record["type"], INSTANCE_CHECK);
    assert_eq!(
        record["subject"],
        json!({ "target": "sandbox-local", "ca_sha256": "ca" })
    );
    assert_eq!(record["tool"]["name"], "polar-sign");
    assert_eq!(record["checked_at_unix_secs"], 7);
    assert_eq!(record["result"]["passed"], false);
    assert!(
        record["result"]["problems"]
            .as_array()
            .unwrap()
            .contains(&json!("pairs-connected: violated"))
    );
    let verdicts = record["verdicts"].as_array().unwrap();
    assert_eq!(verdicts.len(), checked.verdicts.len());
    assert_eq!(verdicts[0]["id"], "pairs-connected");
    assert_eq!(verdicts[0]["verdict"], "violated");
    let projection = record["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["section"] == "projection")
        .unwrap();
    assert_eq!(projection["version"], 3);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// The verdicts do not depend on the order the facts were read in.
    #[test]
    fn the_verdicts_do_not_depend_on_the_order_of_the_facts(
        workloads in Just(base().model.workloads).prop_shuffle(),
        sections in Just(base().sections).prop_shuffle(),
    ) {
        let mut facts = base();
        facts.model.workloads = workloads;
        facts.sections = sections;
        prop_assert_eq!(check(&facts), check(&base()));
    }

    /// Certification holds exactly when every workload that is not a bootstrap service has the credentials agent for its
    /// issuer, read here from the issuers alone.
    #[test]
    fn certification_holds_exactly_when_every_issuer_says_so(
        issuers in proptest::collection::vec(prop_oneof![Just(CREDENTIALS_AGENT), Just("cert-issuer")], 22),
    ) {
        let mut facts = base();
        for (w, issuer) in facts.model.workloads.iter_mut().zip(&issuers) {
            w.issuer = issuer.to_string();
        }
        let expected = facts.model.workloads.iter().all(|w| w.bootstrap || w.issuer == CREDENTIALS_AGENT);
        let (got, witness) = status(&facts, "certified-by-the-credentials-agent");
        prop_assert_eq!(got == Status::Holds, expected, "{:?}", witness);
    }

    /// One owner per label holds exactly when each label some deployed scaffold owns has one owner, and the schema names
    /// it, read here from the assignment alone.
    #[test]
    fn one_owner_holds_exactly_when_each_label_has_one_owner_the_schema_names(
        owners in proptest::collection::vec(proptest::sample::subsequence(vec!["jira-processor", "kube-consumer"], 0..=2), 2),
    ) {
        let mut facts = base();
        let labels = ["JiraIssue", "Pod"];
        let mut by: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (label, holders) in labels.iter().zip(&owners) {
            for holder in holders {
                by.entry(*holder).or_default().push(label);
            }
        }
        for (holder, owns) in &by {
            facts.scaffolds.insert(holder.to_string(), other_scaffold(holder, owns));
        }
        // The schema names each label's first owner.
        let schema = facts.sections.iter_mut().find(|s| s.name == "schema").unwrap();
        let entries = schema.body["workloads"].as_array_mut().unwrap();
        for (label, holders) in labels.iter().zip(&owners) {
            if let Some(first) = holders.first() {
                entries.push(json!({ "workload": first, "owns": [label] }));
            }
        }
        let expected = owners.iter().all(|holders| holders.len() <= 1);
        let (got, witness) = status(&facts, "one-owner-per-label");
        prop_assert_eq!(got == Status::Holds, expected, "{:?}", witness);
    }
}

fn heard(pod: &str, version: u64, body_sha256: &str, build: &str) -> polar_running_config::Heard {
    use polar_scheduler_common::running::{RunningBuild, RunningConfiguration, RunningSection};
    polar_running_config::Heard {
        agent: PROCESSOR.into(),
        instance: Some(format!("uid-{pod}")),
        pod: Some(pod.into()),
        answer: RunningConfiguration {
            id: "q".into(),
            agent: PROCESSOR.into(),
            version: 0,
            settings: vec![],
            sections: vec![RunningSection {
                name: "projection".into(),
                version,
                id: format!("{PROCESSOR}-projection"),
                body_sha256: body_sha256.into(),
            }],
            build: RunningBuild {
                name: PROCESSOR.into(),
                version: build.into(),
                release: true,
                target: "t".into(),
            },
            at_unix_secs: 1,
        },
    }
}

/// The base, with the processor asked and its one pod holding what is signed.
fn asked() -> FactBase {
    let mut facts = base();
    let signed = facts
        .section(PROCESSOR, "projection")
        .unwrap()
        .body_sha256
        .clone();
    facts.running = Some(Running {
        asked: vec![PROCESSOR.into()],
        heard: vec![heard("p-1", 3, &signed, "9.9.9")],
    });
    facts
}

#[test]
fn asked_or_not_the_running_invariants_are_judged_only_when_the_agents_were_asked() {
    let ids = |f: &FactBase| check(f).verdicts.iter().map(|v| v.id).collect::<Vec<_>>();
    assert!(!ids(&base()).contains(&"sections-in-force"));
    let checked = check(&asked());
    for id in ["sections-in-force", "running-as-scaffolded"] {
        let v = verdict_of(&checked, id);
        assert_eq!(v.status, Status::Holds, "{id}: {:#?}", v.witness);
    }
    assert!(a_line(
        &verdict_of(&checked, "sections-in-force").witness,
        "openapi-processor (p-1): projection version 3"
    ));
    let record = record(&asked(), &checked, 1);
    let answers = record["running"]["answers"].as_array().unwrap();
    assert_eq!(answers[0]["pod"], "p-1");
    assert!(
        answers[0].get("settings").is_none(),
        "never a setting's value"
    );
}

#[test]
fn a_pod_that_holds_other_than_what_is_signed_violates_sections_in_force() {
    let violated = |facts: &FactBase| status(facts, "sections-in-force");

    let mut silent = asked();
    silent.running.as_mut().unwrap().heard.clear();
    assert_eq!(
        violated(&silent),
        (
            Status::Violated,
            vec!["openapi-processor did not answer".to_string()]
        )
    );

    let mut behind = asked();
    behind
        .running
        .as_mut()
        .unwrap()
        .heard
        .push(heard("p-2", 2, "old", "9.9.9"));
    let (got, witness) = violated(&behind);
    assert_eq!(got, Status::Violated);
    assert_eq!(
        witness,
        [
            "openapi-processor (p-2) holds projection version 2 (document openapi-processor-projection), and version 3 (document openapi-processor-projection) is signed"
        ]
    );

    // The same body signed again at a higher version, which the pod has not applied.
    let mut resigned = asked();
    resigned.running.as_mut().unwrap().heard[0].answer.sections[0].version = 2;
    let (got, witness) = violated(&resigned);
    assert_eq!(got, Status::Violated);
    assert!(
        a_line(&witness, "holds projection version 2"),
        "{witness:#?}"
    );

    let mut other_body = asked();
    other_body.running.as_mut().unwrap().heard[0]
        .answer
        .sections[0]
        .body_sha256 = "another".into();
    assert!(a_line(&violated(&other_body).1, "with another body"));

    let mut stranger = asked();
    let mut extra = stranger.running.as_ref().unwrap().heard[0].answer.sections[0].clone();
    extra.name = "sources".into();
    stranger.running.as_mut().unwrap().heard[0]
        .answer
        .sections
        .push(extra);
    assert!(a_line(
        &violated(&stranger).1,
        "holds sources version 3, which polar-schedules does not sign"
    ));

    let mut unheld = asked();
    unheld.running.as_mut().unwrap().heard[0]
        .answer
        .sections
        .clear();
    assert!(a_line(
        &violated(&unheld).1,
        "holds no projection, and version 3 is signed"
    ));

    let mut settings = asked();
    settings.settings.push(Settings {
        agent: PROCESSOR.into(),
        id: "s".into(),
        version: 2,
        file: "permanent/openapi-processor/configuration.dhall".into(),
    });
    assert_eq!(
        violated(&settings).1,
        ["openapi-processor (p-1) applied settings version 0, and version 2 is signed"]
    );
    settings.running.as_mut().unwrap().heard[0].answer.version = 2;
    assert_eq!(violated(&settings).0, Status::Holds);
}

#[test]
fn a_pod_of_another_build_than_its_scaffold_violates_running_as_scaffolded() {
    let mut facts = asked();
    facts.running.as_mut().unwrap().heard[0]
        .answer
        .build
        .version = "9.9.10+dev".into();
    assert_eq!(
        status(&facts, "running-as-scaffolded"),
        (
            Status::Violated,
            vec![
                "openapi-processor (p-1) runs 9.9.10+dev, and its scaffold is of 9.9.9".to_string()
            ]
        )
    );
}

#[test]
fn a_section_signed_for_versions_its_agent_is_not_violates_sections_in_range() {
    assert_eq!(
        status(&base(), "sections-in-range").1,
        ["no section in force names a range"]
    );
    let ranged = |from: &str, facts: &mut FactBase| {
        let section = facts
            .sections
            .iter_mut()
            .find(|s| s.name == "projection")
            .unwrap();
        section.versions = polar_version::VersionRange {
            from: Some(polar_version::PlatformVersion::parse(from).unwrap()),
            below: None,
        };
    };
    // Offline, by the build the scaffold is of (9.9.9).
    let mut holds = base();
    ranged("9.9.9", &mut holds);
    assert_eq!(status(&holds, "sections-in-range").0, Status::Holds);
    let mut outside = base();
    ranged("10.0.0", &mut outside);
    assert_eq!(
        status(&outside, "sections-in-range"),
        (
            Status::Violated,
            vec!["openapi-processor projection version 3 (from 10.0.0): openapi-processor's scaffold is 9.9.9, outside it".to_string()]
        )
    );
    // Asked, by the build each pod runs.
    let mut running = asked();
    ranged("9.9.9", &mut running);
    running.running.as_mut().unwrap().heard[0]
        .answer
        .build
        .version = "9.9.8".into();
    assert!(a_line(
        &status(&running, "sections-in-range").1,
        "openapi-processor (p-1) is 9.9.8, outside it"
    ));
}

#[test]
fn a_migration_intended_and_never_applied_or_not_the_file_signed_violates_migrations_applied() {
    assert_eq!(
        status(&base(), "migrations-applied").1,
        ["no section in force names a migration"]
    );
    let sha = crate::migration_sha256(b"MATCH (n:OpenApiEndpoint) SET n.kind = 'operation'");
    let named = |facts: &mut FactBase| {
        let section = facts
            .sections
            .iter_mut()
            .find(|s| s.name == "projection")
            .unwrap();
        section.migrations = vec![crate::Migration {
            id: "m1".into(),
            sha256: sha.clone(),
            after: false,
        }];
        facts
            .migration_files
            .insert((PROCESSOR.into(), "m1".into()), sha.clone());
    };
    let applied = |sha256: &str| Applied {
        agent: PROCESSOR.into(),
        section: "projection".into(),
        migration: "m1".into(),
        sha256: sha256.into(),
        signer: "alice".into(),
        file: "migrations/openapi-processor/m1.applied.dhall".into(),
    };
    let mut never = base();
    named(&mut never);
    assert_eq!(
        status(&never, "migrations-applied").1,
        [
            "openapi-processor projection version 3: migration m1: intended, and no record says it was applied"
        ]
    );
    let mut done = base();
    named(&mut done);
    done.applied.push(applied(&sha));
    assert_eq!(status(&done, "migrations-applied").0, Status::Holds);
    let mut other = base();
    named(&mut other);
    other.applied.push(applied("another"));
    assert_eq!(status(&other, "migrations-applied").0, Status::Violated);
    let mut changed = base();
    named(&mut changed);
    changed.applied.push(applied(&sha));
    changed
        .migration_files
        .insert((PROCESSOR.into(), "m1".into()), "edited".into());
    assert!(a_line(
        &status(&changed, "migrations-applied").1,
        "its file is not the one signed"
    ));
    let mut missing = base();
    named(&mut missing);
    missing.applied.push(applied(&sha));
    missing.migration_files.clear();
    assert!(a_line(
        &status(&missing, "migrations-applied").1,
        "its file is not at migrations/openapi-processor/m1.cypher"
    ));
}
