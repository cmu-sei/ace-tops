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

//! `polar-sign check`: what one version of one instance declares, judged (docs/architecture/http-observers.md,
//! "Evidence", bite 5). The facts come from the signed repositories as they are read ([`read`]): the deployment (its
//! authority model and its record), `polar-schedules` (every signed section), `polar-evidence`, and the agents'
//! scaffolds. Each invariant has a stable id, and a verdict: it holds, it is violated, or it is no longer covered (there
//! was evidence, for another version), with the lines that show it. Nothing here reads a file or a cluster: a test gives a
//! fact base and reads the verdicts.

pub mod read;

use crate::scaffold::Scaffold;
use credentials_agent_model::facts::CREDENTIALS_AGENT;
use credentials_agent_model::{Action, Allowed, Model, Node, Pair, allowed_under, evaluate};
use polar_topics::Access;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// What a record of this kind says it is.
pub const INSTANCE_CHECK: &str = "instance-check";

/// Which instance: its target and the fingerprint of the CA its documents are signed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub target: String,
    pub ca_sha256: String,
}

/// A signed runtime section of `polar-schedules`, as verified.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub agent: String,
    pub name: String,
    pub id: String,
    pub version: u64,
    pub body: Value,
    /// Of the body, canonically: what a projection test's record names.
    pub body_sha256: String,
    pub signer: String,
    pub file: String,
    /// Which versions of the agent it is for (`target.versions`); every version when it names none.
    pub versions: polar_version::VersionRange,
    /// The migrations it names, which an administrator applies.
    pub migrations: Vec<crate::Migration>,
}

/// A signed record of `polar-schedules` that an administrator applied a migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub agent: String,
    pub section: String,
    pub migration: String,
    pub sha256: String,
    pub signer: String,
    pub file: String,
}

/// A signed evidence record of `polar-evidence`, as verified.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub file: String,
    pub signer: String,
    pub record: Value,
}

/// A workload as the deployment's signed record says it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployed {
    pub identity: String,
    pub owner_kind: String,
    pub images: Vec<String>,
}

/// An agent's scaffold as it was read, and the digest of that text.
#[derive(Debug, Clone, PartialEq)]
pub struct ScaffoldFact {
    pub sha256: String,
    pub document: Value,
}

/// Everything a check judges, of one instance at one version.
#[derive(Debug, Clone)]
pub struct FactBase {
    pub instance: Instance,
    /// The authority model the render gave the credentials agent: every workload by its one identity.
    pub model: Model,
    pub deployed: Vec<Deployed>,
    /// By workload.
    pub scaffolds: BTreeMap<String, ScaffoldFact>,
    pub sections: Vec<Section>,
    pub evidence: Vec<Evidence>,
    /// What was read, by name: each repository's commit, the deployment record's version.
    pub inputs: BTreeMap<String, String>,
    /// Each agent's signed settings document, as verified: what its answer's version should be.
    pub settings: Vec<Settings>,
    /// What the running agents said they hold, when they were asked (`check --ask`).
    pub running: Option<Running>,
    /// Each record that a migration was applied.
    pub applied: Vec<Applied>,
    /// The digest of each migration's file in `polar-schedules` (`migrations/<agent>/<id>.cypher`), by agent and id.
    pub migration_files: BTreeMap<(String, String), String>,
}

/// An agent's signed settings document (`type: configuration`) of `polar-schedules`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub agent: String,
    pub id: String,
    pub version: u64,
    pub file: String,
}

/// The running agents, asked: whom, and every answer each of their pods gave.
#[derive(Debug, Clone, PartialEq)]
pub struct Running {
    pub asked: Vec<String>,
    pub heard: Vec<polar_running_config::Heard>,
}

/// The agents a check asks what they hold: every agent that reads a signed document, which is what answers.
pub fn agents_to_ask(model: &Model) -> Vec<String> {
    model
        .workloads
        .iter()
        .filter(|w| w.kind.as_deref() == Some("agent") && w.config.as_deref() == Some("document"))
        .map(|w| w.workload.clone())
        .collect()
}

/// How an invariant stands, in order of how much it says is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    Holds,
    /// There was evidence for it, for another version than the one in force.
    NoLongerCovered,
    Violated,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Holds => "holds",
            Status::NoLongerCovered => "no-longer-covered",
            Status::Violated => "violated",
        }
    }
}

/// One invariant's verdict: its id, which a claim binds by, its statement, which lives here and nowhere else, and the
/// lines that show its status (those at that status: what holds it, or what breaks it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub id: &'static str,
    pub statement: &'static str,
    pub status: Status,
    pub witness: Vec<String>,
}

/// What a check found: every invariant's verdict, in a fixed order, and what each workload could touch.
#[derive(Debug, Clone, PartialEq)]
pub struct Checked {
    pub verdicts: Vec<Verdict>,
    pub reach: Value,
}

impl Checked {
    pub fn holds(&self) -> bool {
        self.verdicts.iter().all(|v| v.status == Status::Holds)
    }
}

/// The verdict of `findings`: the worst status any says, shown by the lines at that status, each once and in order. With
/// nothing to judge, it holds, and says so.
fn verdict(
    id: &'static str,
    statement: &'static str,
    findings: Vec<(Status, String)>,
    nothing: &str,
) -> Verdict {
    let status = findings
        .iter()
        .map(|(s, _)| *s)
        .max()
        .unwrap_or(Status::Holds);
    let mut witness: Vec<String> = findings
        .into_iter()
        .filter(|(s, _)| *s == status)
        .map(|(_, line)| line)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if witness.is_empty() {
        witness.push(nothing.to_string());
    }
    Verdict {
        id,
        statement,
        status,
        witness,
    }
}

impl FactBase {
    /// The section in force of `agent` named `name`: the highest version signed.
    fn section(&self, agent: &str, name: &str) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| s.agent == agent && s.name == name)
            .max_by(|a, b| (a.version, &a.file).cmp(&(b.version, &b.file)))
    }

    /// Every section in force: the highest version of each agent's each section.
    fn in_force(&self) -> Vec<&Section> {
        let names: BTreeSet<(&str, &str)> = self
            .sections
            .iter()
            .map(|s| (s.agent.as_str(), s.name.as_str()))
            .collect();
        names
            .into_iter()
            .filter_map(|(agent, name)| self.section(agent, name))
            .collect()
    }

    /// The section of `name` whichever agent holds it, for the state agent's, whose agent is named in the catalog.
    fn section_named(&self, name: &str) -> Option<&Section> {
        self.in_force().into_iter().find(|s| s.name == name)
    }

    fn scaffold(&self, workload: &str) -> Option<Scaffold> {
        self.scaffolds
            .get(workload)
            .and_then(|s| Scaffold::parse(&s.document.to_string()).ok())
    }

    /// Whether `agent`'s scaffold says its section `name` holds a projection.
    fn is_projection(&self, agent: &str, name: &str) -> bool {
        self.scaffold(agent)
            .and_then(|s| s.section(name).cloned())
            .and_then(|r| r.body["rules"]["type"].as_str().map(str::to_string))
            .is_some_and(|t| t.starts_with(polar_projection::SECTION_TYPE))
    }

    fn deployed_workloads(&self) -> BTreeSet<&str> {
        self.model
            .workloads
            .iter()
            .map(|w| w.workload.as_str())
            .collect()
    }

    /// The labels each deployed workload's scaffold says it owns, or reads.
    fn labels(&self, access: &str) -> BTreeMap<String, BTreeSet<String>> {
        let mut by_workload: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for workload in self.deployed_workloads() {
            let Some(fact) = self.scaffolds.get(workload) else {
                continue;
            };
            for entry in fact.document["graph"].as_array().into_iter().flatten() {
                if entry["access"] == access
                    && let Some(label) = entry["label"].as_str()
                {
                    by_workload
                        .entry(workload.to_string())
                        .or_default()
                        .insert(label.to_string());
                }
            }
        }
        by_workload
    }
}

/// The pair in force, from the credentials agent's `policy` and `groups` sections; none signed is the floor.
fn pair_in_force(facts: &FactBase) -> Result<Pair, String> {
    Pair::from_sections(
        facts.section(CREDENTIALS_AGENT, "policy").map(|s| &s.body),
        facts.section(CREDENTIALS_AGENT, "groups").map(|s| &s.body),
    )
}

/// Judges every invariant of `facts`.
pub fn check(facts: &FactBase) -> Checked {
    let allowed = pair_in_force(facts).and_then(|pair| allowed_under(&facts.model, &pair, &[]));
    let verdicts = vec![
        pairs_connected(facts, &allowed),
        authority_reaches_every_agent(facts, &allowed),
        one_owner_per_label(facts),
        projections_inside_schema(facts),
        projections_tested(facts),
        certified_by_the_credentials_agent(facts),
        seen_by_health(facts),
        sections_in_range(facts),
        migrations_applied(facts),
    ];
    let mut verdicts = verdicts;
    if let Some(running) = &facts.running {
        verdicts.push(sections_in_force(facts, running));
        verdicts.push(running_as_scaffolded(facts, running));
    }
    Checked {
        verdicts,
        reach: could_touch(facts, &allowed),
    }
}

fn pairs_connected(facts: &FactBase, allowed: &Result<Allowed, String>) -> Verdict {
    const ID: &str = "pairs-connected";
    const STATEMENT: &str = "every workload that publishes a topic reaches every workload that hears it, under the policy \
                             and groups in force";
    let allowed = match allowed {
        Ok(allowed) => allowed,
        Err(e) => {
            return verdict(
                ID,
                STATEMENT,
                vec![(
                    Status::Violated,
                    format!("the policy in force cannot be judged: {e}"),
                )],
                "",
            );
        }
    };
    let evaluation = evaluate(&facts.model, allowed);
    let identity: BTreeMap<&str, &str> = facts
        .model
        .workloads
        .iter()
        .map(|w| (w.workload.as_str(), w.identity.as_str()))
        .collect();
    let mut sides: BTreeMap<&str, (BTreeSet<&str>, BTreeSet<&str>)> = BTreeMap::new();
    for w in &facts.model.workloads {
        for t in &w.topics {
            let side = sides.entry(t.name.as_str()).or_default();
            match t.access {
                Access::Publish => side.0.insert(w.workload.as_str()),
                Access::Subscribe => side.1.insert(w.workload.as_str()),
            };
        }
    }
    let mut findings = Vec::new();
    for (topic, (publishers, hearers)) in &sides {
        for a in publishers {
            for b in hearers {
                let edge = (
                    Node::Out(a.to_string(), topic.to_string()),
                    Node::In(b.to_string(), topic.to_string()),
                );
                if evaluation.edges.contains(&edge) {
                    findings.push((Status::Holds, format!("{a} -> {b} on `{topic}`")));
                    continue;
                }
                let may = |w: &str, action: Action| {
                    allowed.contains(&(identity[w].to_string(), topic.to_string(), action))
                };
                let mut why = Vec::new();
                if !may(a, Action::Publish) {
                    why.push(format!("{a} may not publish it"));
                }
                if !may(b, Action::Subscribe) {
                    why.push(format!("{b} may not hear it"));
                }
                if credentials_agent_model::requests::is_request(topic) && !may(a, Action::Request)
                {
                    why.push(format!("{a} may not request on it"));
                }
                findings.push((
                    Status::Violated,
                    format!(
                        "{a} publishes `{topic}` and {b} hears it, but {}",
                        why.join(" and ")
                    ),
                ));
            }
        }
    }
    verdict(
        ID,
        STATEMENT,
        findings,
        "no topic has both a publisher and a hearer",
    )
}

fn path(nodes: &[Node]) -> String {
    nodes
        .iter()
        .map(|n| match n {
            Node::Out(w, t) => format!("{w} publishes `{t}`"),
            Node::In(w, t) => format!("{w} hears `{t}`"),
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn authority_reaches_every_agent(facts: &FactBase, allowed: &Result<Allowed, String>) -> Verdict {
    const ID: &str = "authority-reaches-every-agent";
    const STATEMENT: &str = "the credentials agent's updates reach every agent, every agent's request for the authority is \
                             answered, and a push reaches the credentials agent's configuration";
    let allowed = match allowed {
        Ok(allowed) => allowed,
        Err(e) => {
            return verdict(
                ID,
                STATEMENT,
                vec![(
                    Status::Violated,
                    format!("the policy in force cannot be judged: {e}"),
                )],
                "",
            );
        }
    };
    let findings = evaluate(&facts.model, allowed)
        .goals
        .iter()
        .map(|goal| match &goal.witness {
            Some(witness) if goal.held => (
                Status::Holds,
                format!("{}: {}", goal.describe(), path(witness)),
            ),
            _ => (Status::Violated, goal.describe()),
        })
        .collect();
    verdict(ID, STATEMENT, findings, "the model has no goal for it")
}

fn one_owner_per_label(facts: &FactBase) -> Verdict {
    const ID: &str = "one-owner-per-label";
    const STATEMENT: &str = "each graph label has one owner, by the scaffolds, and the state agent's schema names that owner";
    let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (workload, labels) in facts.labels("owns") {
        for label in labels {
            owners.entry(label).or_default().insert(workload.clone());
        }
    }
    let schema = facts.section_named("schema");
    let mut in_schema: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let Some(schema) = schema {
        for entry in schema.body["workloads"].as_array().into_iter().flatten() {
            let workload = entry["workload"].as_str().unwrap_or("?");
            for label in entry["owns"].as_array().into_iter().flatten() {
                if let Some(label) = label.as_str() {
                    in_schema
                        .entry(label.to_string())
                        .or_default()
                        .insert(workload.to_string());
                }
            }
        }
    }
    let mut findings = Vec::new();
    if schema.is_none() && !owners.is_empty() {
        findings.push((
            Status::Violated,
            "the state agent has no schema signed".to_string(),
        ));
    }
    let named = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(", ");
    for (label, by) in &owners {
        if by.len() > 1 {
            findings.push((
                Status::Violated,
                format!("{label} is owned by {}", named(by)),
            ));
            continue;
        }
        if schema.is_none() {
            continue;
        }
        match in_schema.get(label) {
            Some(listed) if listed == by => {
                findings.push((Status::Holds, format!("{label}: {}", named(by))))
            }
            Some(listed) => findings.push((
                Status::Violated,
                format!(
                    "{label} is owned by {} by its scaffold and by {} in the state agent's schema",
                    named(by),
                    named(listed)
                ),
            )),
            None => findings.push((
                Status::Violated,
                format!(
                    "{label} is owned by {} and the state agent's schema names no owner",
                    named(by)
                ),
            )),
        }
    }
    for (label, listed) in &in_schema {
        if !owners.contains_key(label) {
            findings.push((
                Status::Violated,
                format!(
                    "{label} is owned by {} in the state agent's schema and by no deployed workload's scaffold",
                    named(listed)
                ),
            ));
        }
    }
    verdict(ID, STATEMENT, findings, "no deployed workload owns a label")
}

/// The projections in force, as each agent's scaffold says which sections hold one.
fn projections(facts: &FactBase) -> Vec<&Section> {
    facts
        .in_force()
        .into_iter()
        .filter(|s| facts.is_projection(&s.agent, &s.name))
        .collect()
}

fn projections_inside_schema(facts: &FactBase) -> Verdict {
    const ID: &str = "projections-inside-schema";
    const STATEMENT: &str = "each projection in force is inside its binary's schema, by the scaffold of the image deployed";
    let mut findings = Vec::new();
    let deployed = facts.deployed_workloads();
    for section in facts.in_force() {
        if deployed.contains(section.agent.as_str())
            && !facts.scaffolds.contains_key(&section.agent)
        {
            findings.push((
                Status::Violated,
                format!(
                    "{} has its {} section signed and no scaffold to judge it by",
                    section.agent, section.name
                ),
            ));
        }
    }
    for section in projections(facts) {
        let at = format!(
            "{} {} version {}",
            section.agent, section.name, section.version
        );
        match facts
            .scaffold(&section.agent)
            .map(|s| s.projection(&section.body))
        {
            Some(Ok(_)) => findings.push((Status::Holds, at)),
            Some(Err(problems)) => {
                findings.push((Status::Violated, format!("{at}: {}", problems.join("; "))))
            }
            None => findings.push((
                Status::Violated,
                format!("{at}: its scaffold cannot be read"),
            )),
        }
    }
    verdict(ID, STATEMENT, findings, "no projection is signed")
}

fn projections_tested(facts: &FactBase) -> Verdict {
    const ID: &str = "projections-tested";
    const STATEMENT: &str = "each projection in force passed a projection test of that body by its agent's scaffold, and \
                             its samples reach every read it makes";
    let mut findings = Vec::new();
    for section in projections(facts) {
        let at = format!(
            "{} {} version {}",
            section.agent, section.name, section.version
        );
        let scaffold = facts
            .scaffolds
            .get(&section.agent)
            .map(|s| s.sha256.as_str());
        let tests: Vec<&Evidence> = facts
            .evidence
            .iter()
            .filter(|e| {
                e.record["type"] == crate::evidence::PROJECTION_TEST
                    && e.record["subject"]["agent"] == section.agent.as_str()
                    && e.record["subject"]["section"] == section.name.as_str()
            })
            .collect();
        let this_version = |e: &Evidence| {
            e.record["mapping"]["body_sha256"] == section.body_sha256.as_str()
                && e.record["scaffold"]["sha256"].as_str() == scaffold
        };
        let passed: Vec<&&Evidence> = tests
            .iter()
            .filter(|e| this_version(e))
            .filter(|e| e.record["result"]["passed"] == true)
            .collect();
        let latest = passed.iter().max_by(|a, b| {
            let at = |e: &Evidence| e.record["tested_at_unix_secs"].as_i64().unwrap_or(0);
            (at(a), &a.file).cmp(&(at(b), &b.file))
        });
        if let Some(test) = latest {
            let unreached: Vec<&str> = test.record["coverage"]["unreached"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if unreached.is_empty() {
                findings.push((
                    Status::Holds,
                    format!("{at}: tested by {} ({})", test.signer, test.file),
                ));
            } else {
                findings.push((
                    Status::Violated,
                    format!(
                        "{at}: tested ({}), and no sample reaches {}",
                        test.file,
                        unreached.join(", ")
                    ),
                ));
            }
        } else if tests.iter().any(|e| this_version(e)) {
            findings.push((
                Status::Violated,
                format!("{at}: its test at this version failed"),
            ));
        } else if !tests.is_empty() {
            findings.push((
                Status::NoLongerCovered,
                format!(
                    "{at}: tested at another version of the body or the scaffold, not at this one"
                ),
            ));
        } else {
            findings.push((Status::Violated, format!("{at}: never tested")));
        }
    }
    verdict(ID, STATEMENT, findings, "no projection is signed")
}

fn certified_by_the_credentials_agent(facts: &FactBase) -> Verdict {
    const ID: &str = "certified-by-the-credentials-agent";
    const STATEMENT: &str = "every workload that is not a bootstrap service is issued its certificates by the credentials agent";
    let findings = facts
        .model
        .workloads
        .iter()
        .filter(|w| !w.bootstrap)
        .map(|w| {
            if w.issuer == CREDENTIALS_AGENT {
                (Status::Holds, w.workload.clone())
            } else {
                (
                    Status::Violated,
                    format!("{} is issued by {}", w.workload, w.issuer),
                )
            }
        })
        .collect();
    verdict(
        ID,
        STATEMENT,
        findings,
        "every workload is a bootstrap service",
    )
}

fn seen_by_health(facts: &FactBase) -> Verdict {
    const ID: &str = "seen-by-health";
    const STATEMENT: &str = "every agent that reads a signed document is in the state agent's agents list, by its identity, \
                             and nothing else is";
    if facts
        .model
        .workloads
        .iter()
        .any(|w| w.kind.is_none() || w.config.is_none())
    {
        return verdict(
            ID,
            STATEMENT,
            vec![(
                Status::Violated,
                "the authority model was rendered before it said each workload's kind and configuration: render again"
                    .to_string(),
            )],
            "",
        );
    }
    let expected: BTreeMap<&str, &str> = facts
        .model
        .workloads
        .iter()
        .filter(|w| w.kind.as_deref() == Some("agent") && w.config.as_deref() == Some("document"))
        .map(|w| (w.identity.as_str(), w.workload.as_str()))
        .collect();
    let Some(agents) = facts.section_named("agents") else {
        let findings = if expected.is_empty() {
            Vec::new()
        } else {
            vec![(
                Status::Violated,
                "the state agent's writer has no agents list signed".to_string(),
            )]
        };
        return verdict(ID, STATEMENT, findings, "no agent reads a signed document");
    };
    let listed: BTreeSet<&str> = agents.body["workloads"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w["identity"].as_str())
        .collect();
    let mut findings = Vec::new();
    for (identity, workload) in &expected {
        if listed.contains(identity) {
            findings.push((Status::Holds, workload.to_string()));
        } else {
            findings.push((
                Status::Violated,
                format!(
                    "{workload} ({identity}) is not in the agents list, so its health is not asked"
                ),
            ));
        }
    }
    for identity in listed.difference(&expected.keys().copied().collect()) {
        findings.push((
            Status::Violated,
            format!("{identity} is in the agents list and is no agent of this deployment that reads a document"),
        ));
    }
    verdict(ID, STATEMENT, findings, "no agent reads a signed document")
}

fn sections_in_range(facts: &FactBase) -> Verdict {
    const ID: &str = "sections-in-range";
    const STATEMENT: &str = "each section in force that names a range of versions holds the agent's build: the one each pod \
                             runs when asked, or the one its scaffold is of";
    let mut findings = Vec::new();
    for section in facts.in_force() {
        if section.versions == polar_version::VersionRange::default() {
            continue;
        }
        let at = format!(
            "{} {} version {} ({})",
            section.agent, section.name, section.version, section.versions
        );
        let builds: Vec<(String, String)> = match &facts.running {
            Some(running) => running
                .heard
                .iter()
                .filter(|h| h.agent == section.agent)
                .map(|h| (pod_of(h), h.answer.build.version.clone()))
                .collect(),
            None => facts
                .scaffolds
                .get(&section.agent)
                .and_then(|s| s.document["agent"]["version"]["version"].as_str())
                .map(|v| vec![(format!("{}'s scaffold", section.agent), v.to_string())])
                .unwrap_or_default(),
        };
        if builds.is_empty() {
            findings.push((Status::Violated, format!("{at}: no build of it is known")));
        }
        for (who, build) in builds {
            match polar_version::PlatformVersion::parse(&build) {
                Ok(v) if section.versions.includes(v) => {
                    findings.push((Status::Holds, format!("{at}: {who} is {build}")))
                }
                Ok(_) => findings.push((
                    Status::Violated,
                    format!("{at}: {who} is {build}, outside it"),
                )),
                Err(e) => findings.push((
                    Status::Violated,
                    format!("{at}: {who} says {build}, not a version: {e}"),
                )),
            }
        }
    }
    verdict(ID, STATEMENT, findings, "no section in force names a range")
}

fn migrations_applied(facts: &FactBase) -> Verdict {
    const ID: &str = "migrations-applied";
    const STATEMENT: &str = "every migration a section in force names is in polar-schedules as signed, by its digest, and a \
                             signed record says it was applied";
    let mut findings = Vec::new();
    for section in facts.in_force() {
        for migration in &section.migrations {
            let at = format!(
                "{} {} version {}: migration {}",
                section.agent, section.name, section.version, migration.id
            );
            match facts
                .migration_files
                .get(&(section.agent.clone(), migration.id.clone()))
            {
                None => findings.push((
                    Status::Violated,
                    format!(
                        "{at}: its file is not at migrations/{}/{}.cypher",
                        section.agent, migration.id
                    ),
                )),
                Some(sha256) if *sha256 != migration.sha256 => findings.push((
                    Status::Violated,
                    format!("{at}: its file is not the one signed (its digest is {sha256})"),
                )),
                Some(_) => {}
            }
            let record = facts.applied.iter().find(|a| {
                a.agent == section.agent
                    && a.migration == migration.id
                    && a.sha256 == migration.sha256
            });
            match record {
                Some(a) => findings.push((
                    Status::Holds,
                    format!("{at}: applied, by {} ({})", a.signer, a.file),
                )),
                None => findings.push((
                    Status::Violated,
                    format!("{at}: intended, and no record says it was applied"),
                )),
            }
        }
    }
    verdict(
        ID,
        STATEMENT,
        findings,
        "no section in force names a migration",
    )
}

/// Which pod, as a line says it.
fn pod_of(heard: &polar_running_config::Heard) -> String {
    match (&heard.pod, &heard.instance) {
        (Some(pod), _) => format!("{} ({pod})", heard.agent),
        (None, Some(uid)) => format!("{} (instance {uid})", heard.agent),
        (None, None) => heard.agent.clone(),
    }
}

fn sections_in_force(facts: &FactBase, running: &Running) -> Verdict {
    const ID: &str = "sections-in-force";
    const STATEMENT: &str = "every agent asked answers, and each of its pods holds the sections and settings signed for it, \
                             by document id, version and body digest";
    let mut findings = Vec::new();
    for agent in &running.asked {
        let answers: Vec<&polar_running_config::Heard> =
            running.heard.iter().filter(|h| &h.agent == agent).collect();
        if answers.is_empty() {
            findings.push((Status::Violated, format!("{agent} did not answer")));
            continue;
        }
        let signed: BTreeMap<&str, &Section> = facts
            .in_force()
            .into_iter()
            .filter(|s| &s.agent == agent)
            .map(|s| (s.name.as_str(), s))
            .collect();
        let settings = facts
            .settings
            .iter()
            .filter(|s| &s.agent == agent)
            .max_by_key(|s| s.version);
        for heard in answers {
            let who = pod_of(heard);
            let held: BTreeMap<&str, &polar_scheduler_common::running::RunningSection> = heard
                .answer
                .sections
                .iter()
                .map(|s| (s.name.as_str(), s))
                .collect();
            for (name, section) in &signed {
                match held.get(name) {
                    Some(h) if h.id == section.id && h.version == section.version && h.body_sha256 == section.body_sha256 => {
                        findings.push((Status::Holds, format!("{who}: {name} version {}", h.version)))
                    }
                    Some(h) => findings.push((
                        Status::Violated,
                        format!(
                            "{who} holds {name} version {} (document {}), and version {} (document {}) is signed{}",
                            h.version,
                            h.id,
                            section.version,
                            section.id,
                            if h.version == section.version && h.id == section.id { ", with another body" } else { "" }
                        ),
                    )),
                    None => findings.push((
                        Status::Violated,
                        format!("{who} holds no {name}, and version {} is signed", section.version),
                    )),
                }
            }
            for (name, h) in &held {
                if !signed.contains_key(name) {
                    findings.push((
                        Status::Violated,
                        format!(
                            "{who} holds {name} version {}, which polar-schedules does not sign",
                            h.version
                        ),
                    ));
                }
            }
            let expected = settings.map_or(0, |s| s.version);
            if heard.answer.version == expected {
                findings.push((Status::Holds, format!("{who}: settings version {expected}")));
            } else {
                findings.push((
                    Status::Violated,
                    format!(
                        "{who} applied settings version {}, and version {expected} is signed",
                        heard.answer.version
                    ),
                ));
            }
        }
    }
    verdict(ID, STATEMENT, findings, "no agent was asked")
}

fn running_as_scaffolded(facts: &FactBase, running: &Running) -> Verdict {
    const ID: &str = "running-as-scaffolded";
    const STATEMENT: &str =
        "each agent runs the build its scaffold, which the check judged by, came from";
    let mut findings = Vec::new();
    for heard in &running.heard {
        let Some(scaffold) = facts.scaffolds.get(&heard.agent) else {
            continue;
        };
        let who = pod_of(heard);
        match scaffold.document["agent"]["version"]["version"].as_str() {
            Some(version) if version == heard.answer.build.version => {
                findings.push((Status::Holds, format!("{who}: {version}")))
            }
            Some(version) => findings.push((
                Status::Violated,
                format!(
                    "{who} runs {}, and its scaffold is of {version}",
                    heard.answer.build.version
                ),
            )),
            None => findings.push((
                Status::Violated,
                format!(
                    "{who} runs {}, and its scaffold says no version",
                    heard.answer.build.version
                ),
            )),
        }
    }
    verdict(ID, STATEMENT, findings, "no agent with a scaffold answered")
}

/// The hosts a body names: every text under a `url`, by its host.
fn hosts(body: &Value, into: &mut BTreeSet<String>) {
    match body {
        Value::Object(map) => {
            for (name, value) in map {
                if name == "url"
                    && let Some(url) = value.as_str()
                    && let Ok(parsed) = reqwest::Url::parse(url)
                    && let Some(host) = parsed.host_str()
                {
                    into.insert(host.to_string());
                }
                hosts(value, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| hosts(v, into)),
        _ => {}
    }
}

/// What each workload could touch, as a report and not a verdict: the topics the pair in force lets it publish and hear,
/// the labels its scaffold says it owns and reads, and the hosts its sections in force name.
fn could_touch(facts: &FactBase, allowed: &Result<Allowed, String>) -> Value {
    let owns = facts.labels("owns");
    let reads = facts.labels("reads");
    let mut report = serde_json::Map::new();
    for w in &facts.model.workloads {
        let topics = |action: Action| -> Vec<&str> {
            allowed
                .as_ref()
                .map(|allowed| {
                    allowed
                        .iter()
                        .filter(|(who, _, a)| *who == w.identity && *a == action)
                        .map(|(_, topic, _)| topic.as_str())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut named = BTreeSet::new();
        for section in facts.in_force().iter().filter(|s| s.agent == w.workload) {
            hosts(&section.body, &mut named);
        }
        let labels = |of: &BTreeMap<String, BTreeSet<String>>| -> Vec<String> {
            of.get(&w.workload).into_iter().flatten().cloned().collect()
        };
        report.insert(
            w.workload.clone(),
            json!({
                "publishes": topics(Action::Publish),
                "hears": topics(Action::Subscribe),
                "owns": labels(&owns),
                "reads": labels(&reads),
                "hosts": named,
            }),
        );
    }
    Value::Object(report)
}

/// Where a signed check goes in the evidence repository: under its kind and target, named by its own digest.
pub fn place(target: &str, signed: &str) -> String {
    use sha2::Digest;
    format!(
        "{INSTANCE_CHECK}/{target}/{}.json",
        hex::encode(sha2::Sha256::digest(signed.as_bytes()))
    )
}

/// The commit message for a check.
pub fn message(target: &str, checked: &Checked, signer: &str) -> String {
    let holding = checked
        .verdicts
        .iter()
        .filter(|v| v.status == Status::Holds)
        .count();
    format!(
        "test({target}): {holding} of {} invariants hold\n\nChecked by {signer} with polar-sign.",
        checked.verdicts.len()
    )
}

/// The record of a check: the common envelope (`type`, `subject`, the digests and versions it is true of, `tool`,
/// `result`, the time), with each verdict and what each workload could touch beside it. Report only: `passed` says
/// whether every invariant holds, and the tool does not fail when one does not.
pub fn record(facts: &FactBase, checked: &Checked, now: i64) -> Value {
    let sections: Vec<Value> = facts
        .in_force()
        .into_iter()
        .map(|s| {
            json!({
                "agent": s.agent, "section": s.name, "id": s.id, "version": s.version,
                "body_sha256": s.body_sha256, "signer": s.signer,
            })
        })
        .collect();
    let scaffolds: BTreeMap<&str, &str> = facts
        .scaffolds
        .iter()
        .map(|(w, s)| (w.as_str(), s.sha256.as_str()))
        .collect();
    let images: Vec<Value> = facts
        .deployed
        .iter()
        .map(|d| json!({ "identity": d.identity, "owner_kind": d.owner_kind, "images": d.images }))
        .collect();
    let problems: Vec<String> = checked
        .verdicts
        .iter()
        .filter(|v| v.status != Status::Holds)
        .map(|v| format!("{}: {}", v.id, v.status.as_str()))
        .collect();
    json!({
        "type": INSTANCE_CHECK,
        "subject": { "target": facts.instance.target, "ca_sha256": facts.instance.ca_sha256 },
        "inputs": facts.inputs,
        "deployed": images,
        "scaffolds": scaffolds,
        "sections": sections,
        "evidence": facts.evidence.iter().map(|e| e.file.as_str()).collect::<Vec<_>>(),
        "tool": polar_version::record("polar-sign"),
        "verdicts": checked.verdicts.iter().map(|v| json!({
            "id": v.id, "statement": v.statement, "verdict": v.status.as_str(), "witness": v.witness,
        })).collect::<Vec<_>>(),
        "reach": checked.reach,
        "running": facts.running.as_ref().map(|r| json!({
            "asked": r.asked,
            // What each pod holds, never its settings' values.
            "answers": r.heard.iter().map(|h| json!({
                "agent": h.agent, "instance": h.instance, "pod": h.pod,
                "build": h.answer.build, "settings_version": h.answer.version, "sections": h.answer.sections,
            })).collect::<Vec<_>>(),
        })),
        "result": { "passed": problems.is_empty(), "problems": problems },
        "checked_at_unix_secs": now,
    })
}

#[cfg(test)]
mod tests;
