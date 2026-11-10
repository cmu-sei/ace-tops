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

//! What the deployment's signed record says, and where what is deployed differs from it (docs/architecture/runtime-attestation.md,
//! "What the images are checked against"). Whether a record is to be believed is the agent's to check, before it comes here.
//!
//! The instance check holds a pod to its owner, which cannot deadlock a rollout. This is the other half: every owner held to the
//! record, continually. A pin changed behind Flux gets a certificate first and is caught here.

use crate::verdict::{Hardening, OwnerKind, WorkloadFacts};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The shapes of record this reads: 1, and 2, which says of each workload whether a configuration under test made it
/// (docs/architecture/configurations-under-test.md, CT2).
const SCHEMAS: [u64; 3] = [1, 2, 3];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentRecord {
    pub schema: u64,
    pub target: String,
    /// It moves when the facts do. An older one than is held is refused.
    pub version: u64,
    pub workloads: Vec<RecordedWorkload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedWorkload {
    pub identity: String,
    pub owner_kind: OwnerKind,
    pub owner_name: String,
    pub namespace: String,
    pub service_account: String,
    pub containers: Vec<RecordedContainer>,
    /// A configuration under test made it: what is said of it is said apart. Schema 2's; in schema 1 none is.
    #[serde(default)]
    pub under_test: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedContainer {
    pub name: String,
    pub image: String,
    /// How it was rendered to run (slice C, C1). Schema 3's; an older schema says nothing of it.
    #[serde(default)]
    pub hardening: Option<Hardening>,
}

impl DeploymentRecord {
    /// Reads a verified document's payload.
    pub fn from_payload(payload: &Value) -> Result<Self, String> {
        let record: DeploymentRecord = serde_json::from_value(payload.clone())
            .map_err(|e| format!("the record does not read: {e}"))?;
        if !SCHEMAS.contains(&record.schema) {
            return Err(format!(
                "a record of schema {}, and this reads {SCHEMAS:?}",
                record.schema
            ));
        }
        if record.schema == 1 && record.workloads.iter().any(|w| w.under_test) {
            return Err("a record of schema 1 marks nothing under test".to_string());
        }
        let says_hardening = record
            .workloads
            .iter()
            .flat_map(|w| &w.containers)
            .any(|c| c.hardening.is_some());
        if record.schema < 3 && says_hardening {
            return Err(format!(
                "a record of schema {} says nothing of how a container runs",
                record.schema
            ));
        }
        Ok(record)
    }

    /// The workload the record says runs in `namespace` under `service_account`. Two workloads that share one say nothing about a
    /// pod.
    pub fn claimed(&self, namespace: &str, service_account: &str) -> Option<&RecordedWorkload> {
        let mut named = self
            .workloads
            .iter()
            .filter(|w| w.namespace == namespace && w.service_account == service_account);
        let workload = named.next()?;
        named.next().is_none().then_some(workload)
    }

    /// Whether the workload `difference` is about is one the record marks under test. One it does not name is not.
    pub fn under_test(&self, difference: &Drift) -> bool {
        let about = difference.workload();
        self.workloads
            .iter()
            .any(|w| w.under_test && named(w.owner_kind, &w.namespace, &w.owner_name) == about)
    }

    /// What it says of the workload `identity` runs as. An identity two workloads share says nothing about either: a catalog workload
    /// has its own service account, so that is not one, and it cannot be told apart by asking.
    pub fn facts_of(&self, identity: &str) -> Option<WorkloadFacts> {
        let mut named = self.workloads.iter().filter(|w| w.identity == identity);
        let workload = named.next()?;
        if named.next().is_some() {
            return None;
        }
        Some(WorkloadFacts {
            owner_kind: workload.owner_kind,
            owner_name: workload.owner_name.clone(),
            service_account: workload.service_account.clone(),
            hardening: hardening_of(workload),
        })
    }
}

/// How the record says each of `workload`'s containers runs, by name: those it says it of.
pub(crate) fn hardening_of(workload: &RecordedWorkload) -> BTreeMap<String, Hardening> {
    workload
        .containers
        .iter()
        .filter_map(|c| c.hardening.map(|h| (c.name.clone(), h)))
        .collect()
}

/// What a Deployment or StatefulSet in the cluster pins, as the platform backend sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployed {
    pub kind: OwnerKind,
    pub namespace: String,
    pub name: String,
    pub pins: BTreeMap<String, String>,
    /// How its pod template makes each container run, by name.
    pub hardening: BTreeMap<String, Hardening>,
}

/// A way what is deployed differs from the record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Drift {
    /// In the cluster, and the record does not name it.
    NotInRecord { workload: String },
    /// The record names it, and the cluster does not hold it.
    NotDeployed { workload: String },
    /// A container the record does not name.
    ContainerNotInRecord { workload: String, container: String },
    /// A container the record names, which its owner does not have.
    ContainerNotDeployed { workload: String, container: String },
    /// A container whose image is not the one the record says.
    AnotherImage {
        workload: String,
        container: String,
        recorded: String,
        found: String,
    },
    /// A container that runs with less than the record says it was rendered with (slice C, C1).
    Weakened {
        workload: String,
        container: String,
        lacks: String,
    },
}

impl Drift {
    /// The workload it is about, as `drift` names it.
    pub fn workload(&self) -> &str {
        match self {
            Drift::NotInRecord { workload }
            | Drift::NotDeployed { workload }
            | Drift::ContainerNotInRecord { workload, .. }
            | Drift::ContainerNotDeployed { workload, .. }
            | Drift::AnotherImage { workload, .. }
            | Drift::Weakened { workload, .. } => workload,
        }
    }
}

fn named(kind: OwnerKind, namespace: &str, name: &str) -> String {
    format!("{kind:?} {namespace}/{name}")
}

/// Where `deployed` differs from `record`, in the namespaces it can see. A Job is not held to it: it finishes and goes, and the record
/// names it only for who runs as it.
pub fn drift(
    record: &DeploymentRecord,
    deployed: &[Deployed],
    watched: &[String],
) -> BTreeSet<Drift> {
    let mut found = BTreeSet::new();
    let recorded: BTreeMap<String, &RecordedWorkload> = record
        .workloads
        .iter()
        .filter(|w| w.owner_kind != OwnerKind::Job && watched.contains(&w.namespace))
        .map(|w| (named(w.owner_kind, &w.namespace, &w.owner_name), w))
        .collect();
    let held: BTreeMap<String, &Deployed> = deployed
        .iter()
        .filter(|d| d.kind != OwnerKind::Job)
        .map(|d| (named(d.kind, &d.namespace, &d.name), d))
        .collect();
    for workload in held.keys().filter(|n| !recorded.contains_key(*n)) {
        found.insert(Drift::NotInRecord {
            workload: workload.clone(),
        });
    }
    for (workload, wanted) in &recorded {
        let Some(actual) = held.get(workload) else {
            found.insert(Drift::NotDeployed {
                workload: workload.clone(),
            });
            continue;
        };
        for container in &wanted.containers {
            match actual.pins.get(&container.name) {
                None => {
                    found.insert(Drift::ContainerNotDeployed {
                        workload: workload.clone(),
                        container: container.name.clone(),
                    });
                }
                Some(image) if *image != container.image => {
                    found.insert(Drift::AnotherImage {
                        workload: workload.clone(),
                        container: container.name.clone(),
                        recorded: container.image.clone(),
                        found: image.clone(),
                    });
                }
                Some(_) => {
                    if let Some(wanted) = &container.hardening {
                        let held = actual
                            .hardening
                            .get(&container.name)
                            .copied()
                            .unwrap_or_default();
                        let lacks = held.lacks(wanted);
                        if !lacks.is_empty() {
                            found.insert(Drift::Weakened {
                                workload: workload.clone(),
                                container: container.name.clone(),
                                lacks: lacks.join(", "),
                            });
                        }
                    }
                }
            }
        }
        for container in actual.pins.keys() {
            if !wanted.containers.iter().any(|c| c.name == *container) {
                found.insert(Drift::ContainerNotInRecord {
                    workload: workload.clone(),
                    container: container.clone(),
                });
            }
        }
    }
    found
}

/// Which differences have lasted. A record and what Flux applies from the same commit do not arrive together, so a difference is
/// reported once it has lasted `grace_secs`, once, and again as gone only if it was reported.
#[derive(Debug, Clone)]
pub struct DriftWatch {
    grace_secs: u64,
    since: BTreeMap<Drift, u64>,
    reported: BTreeSet<Drift>,
}

/// What to say after a look.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriftChanges {
    pub lasting: Vec<Drift>,
    pub gone: Vec<Drift>,
}

impl DriftWatch {
    pub fn new(grace_secs: u64) -> Self {
        DriftWatch {
            grace_secs,
            since: BTreeMap::new(),
            reported: BTreeSet::new(),
        }
    }

    /// Takes what differs at `now`, in seconds.
    pub fn observe(&mut self, now: u64, current: &BTreeSet<Drift>) -> DriftChanges {
        self.since.retain(|d, _| current.contains(d));
        for d in current {
            self.since.entry(d.clone()).or_insert(now);
        }
        let gone: Vec<Drift> = self.reported.difference(current).cloned().collect();
        for d in &gone {
            self.reported.remove(d);
        }
        let lasting: Vec<Drift> = self
            .since
            .iter()
            .filter(|(d, at)| {
                now.saturating_sub(**at) >= self.grace_secs && !self.reported.contains(*d)
            })
            .map(|(d, _)| d.clone())
            .collect();
        self.reported.extend(lasting.iter().cloned());
        DriftChanges { lasting, gone }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn payload() -> Value {
        json!({
            "schema": 1, "target": "t", "version": 4,
            "workloads": [{
                "identity": "the-app.polar.serviceaccount.cluster.local",
                "owner_kind": "Deployment", "owner_name": "the-app", "namespace": "polar",
                "service_account": "the-app",
                "containers": [{ "name": "the-app", "image": "r/app@sha256:aa" }]
            }]
        })
    }

    #[test]
    fn a_record_says_what_an_identity_runs_as() {
        let record = DeploymentRecord::from_payload(&payload()).unwrap();
        assert_eq!(record.version, 4);
        assert_eq!(
            record.facts_of("the-app.polar.serviceaccount.cluster.local"),
            Some(WorkloadFacts {
                owner_kind: OwnerKind::Deployment,
                owner_name: "the-app".into(),
                service_account: "the-app".into(),
                hardening: BTreeMap::new(),
            })
        );
        assert_eq!(record.facts_of("someone-else"), None);
    }

    // Slice C, C1: schema 3 says how each container is made to run, and what an identity runs as carries it; an older schema
    // says nothing of it, and a record that does not say it in its schema is refused.
    #[test]
    fn a_record_of_schema_3_says_how_each_container_runs() {
        let mut payload = payload();
        payload["schema"] = json!(3);
        payload["workloads"][0]["containers"][0]["hardening"] = json!({ "read_only_root": true, "no_privilege_escalation": true, "confined_seccomp": false });
        let record = DeploymentRecord::from_payload(&payload).unwrap();
        let facts = record
            .facts_of("the-app.polar.serviceaccount.cluster.local")
            .unwrap();
        assert_eq!(
            facts.hardening.get("the-app"),
            Some(&Hardening {
                read_only_root: true,
                no_privilege_escalation: true,
                confined_seccomp: false,
            })
        );
        let mut older = payload.clone();
        older["schema"] = json!(2);
        assert!(DeploymentRecord::from_payload(&older).is_err());
        let mut stranger = payload;
        stranger["workloads"][0]["containers"][0]["hardening"]["privileged"] = json!(false);
        assert!(DeploymentRecord::from_payload(&stranger).is_err());
        let before = DeploymentRecord::from_payload(&super::tests::payload()).unwrap();
        assert!(
            before
                .facts_of("the-app.polar.serviceaccount.cluster.local")
                .unwrap()
                .hardening
                .is_empty()
        );
    }

    #[test]
    fn two_workloads_on_one_identity_say_nothing_about_it() {
        let mut record = DeploymentRecord::from_payload(&payload()).unwrap();
        record.workloads.push(record.workloads[0].clone());
        assert_eq!(record.facts_of(&record.workloads[0].identity.clone()), None);
    }

    #[test]
    fn a_difference_is_reported_at_exactly_the_grace_and_not_a_second_before() {
        let d: BTreeSet<Drift> = [Drift::NotDeployed {
            workload: "w".into(),
        }]
        .into_iter()
        .collect();
        let mut watch = DriftWatch::new(600);
        assert!(watch.observe(1000, &d).lasting.is_empty());
        assert!(watch.observe(1599, &d).lasting.is_empty());
        assert_eq!(watch.observe(1600, &d).lasting.len(), 1);
    }

    #[test]
    fn a_job_that_has_finished_and_a_namespace_it_cannot_see_are_not_differences() {
        let mut record = DeploymentRecord::from_payload(&payload()).unwrap();
        let the_app = record.workloads[0].clone();
        let mut job = the_app.clone();
        job.owner_kind = OwnerKind::Job;
        job.owner_name = "a-job".into();
        let mut elsewhere = the_app.clone();
        elsewhere.namespace = "not-watched".into();
        elsewhere.owner_name = "elsewhere".into();
        record.workloads.extend([job, elsewhere]);
        let deployed = [Deployed {
            kind: OwnerKind::Deployment,
            namespace: "polar".into(),
            name: "the-app".into(),
            pins: [("the-app".to_string(), "r/app@sha256:aa".to_string())]
                .into_iter()
                .collect(),
            hardening: BTreeMap::new(),
        }];
        assert_eq!(
            drift(&record, &deployed, &["polar".to_string()]),
            BTreeSet::new()
        );
    }

    #[test]
    fn a_schema_2_record_says_which_workloads_are_under_test_and_a_schema_1_says_none_is() {
        let mut two = payload();
        two["schema"] = json!(2);
        two["workloads"][0]["under_test"] = json!(true);
        let record = DeploymentRecord::from_payload(&two).unwrap();
        assert!(record.workloads[0].under_test);
        assert!(record.claimed("polar", "the-app").unwrap().under_test);
        assert!(
            !DeploymentRecord::from_payload(&payload())
                .unwrap()
                .workloads[0]
                .under_test
        );
        // Schema 1 has no mark: one that carries it is not schema 1.
        let mut one = payload();
        one["workloads"][0]["under_test"] = json!(true);
        assert!(DeploymentRecord::from_payload(&one).is_err());
    }

    #[test]
    fn a_difference_says_whether_the_workload_it_is_about_is_under_test() {
        let mut two = payload();
        two["schema"] = json!(2);
        two["workloads"][0]["under_test"] = json!(true);
        let record = DeploymentRecord::from_payload(&two).unwrap();
        let gone = Drift::NotDeployed {
            workload: "Deployment polar/the-app".into(),
        };
        assert_eq!(
            drift(&record, &[], &["polar".to_string()]),
            BTreeSet::from([gone.clone()])
        );
        assert!(record.under_test(&gone));
        // One the record does not name is not under test: nothing says it is.
        assert!(!record.under_test(&Drift::NotInRecord {
            workload: "Deployment polar/a-stranger".into(),
        }));
        assert!(
            !DeploymentRecord::from_payload(&payload())
                .unwrap()
                .under_test(&gone)
        );
    }

    #[test]
    fn a_record_of_another_shape_is_refused() {
        let mut other = payload();
        other["schema"] = json!(4);
        assert!(DeploymentRecord::from_payload(&other).is_err());
        let mut extra = payload();
        extra["surprise"] = json!(true);
        assert!(DeploymentRecord::from_payload(&extra).is_err());
        let mut kind = payload();
        kind["workloads"][0]["owner_kind"] = json!("DaemonSet");
        assert!(DeploymentRecord::from_payload(&kind).is_err());
        assert!(DeploymentRecord::from_payload(&json!({})).is_err());
    }
}
