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

//! The authority model's base facts, as the render writes them (`infra/rules.nu`, `model_facts`), and the pair of
//! documents a judgement is made under.

use cert_issuer_common::capability::Capability;
use cert_issuer_common::hierarchy::Hierarchy;
use polar_topics::TopicEntry;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The issuer the render names for a workload the credentials agent issues (`infra/rules.nu`).
pub const CREDENTIALS_AGENT: &str = "credentials-agent";

/// The format of the model document this crate reads.
pub const FORMAT: u32 = 1;

/// Every workload of a deployment, whoever issues it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Model {
    pub format: u32,
    pub workloads: Vec<Workload>,
}

/// One workload: its name, its one identity (`<workload>.<namespace>.serviceaccount.<domain>`), who issues its
/// certificates, whether it is a bootstrap service, the groups its certificate carries, and its whole set of topics as
/// its scaffold prints them (declared, family and implied), each with what it says about causes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    pub workload: String,
    pub identity: String,
    pub issuer: String,
    pub bootstrap: bool,
    /// How many of its pods run at once (docs/architecture/authority-model.md, "Multi-instance workloads"). Absent in a
    /// model written before it existed, which reads as one.
    #[serde(default)]
    pub instances: Instances,
    /// What the catalog says it is: `agent`, `run`, `ca` or `service`. Absent in a model rendered before it was written,
    /// which says nothing of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// How it is configured: `document` for an agent that reads a signed document (and prints a scaffold), `env` for one
    /// that reads only its environment. Absent as `kind` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub topics: Vec<TopicEntry>,
    /// The evidence record types its pods' signing certificates may sign, from a collector's scaffold
    /// (docs/architecture/key-custody.md, "Workload signing keys"). Absent for a workload that collects nothing, and in
    /// a model written before it existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<String>,
}

/// How many pods of a workload run at once: one, or many, each an instance of the one identity with its own certificate
/// and session, its instance written into its certificates by issuance (docs/architecture/authority-model.md,
/// "Multi-instance workloads").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Instances {
    #[default]
    One,
    Many,
}

impl Model {
    /// The model in `text`. Refused when it is not the document, not its format, or names a workload twice, or by an
    /// identity that is not its own (the model knows a workload by one identity: authority-model.md, "Decisions").
    pub fn parse(text: &str) -> Result<Self, String> {
        let model: Model = serde_json::from_str(text)
            .map_err(|e| format!("the authority model is not its document: {e}"))?;
        if model.format != FORMAT {
            return Err(format!(
                "the authority model is format {}, and this reads format {FORMAT}",
                model.format
            ));
        }
        let mut names = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for w in &model.workloads {
            if !names.insert(w.workload.as_str()) {
                return Err(format!("the authority model names {} twice", w.workload));
            }
            if !identities.insert(w.identity.as_str()) {
                return Err(format!(
                    "the authority model gives two workloads the identity {}",
                    w.identity
                ));
            }
            if cert_issuer_common::identity::workload_of(&w.identity) != Some(w.workload.as_str()) {
                return Err(format!(
                    "{}: its identity {} names another workload",
                    w.workload, w.identity
                ));
            }
        }
        Ok(model)
    }

    /// How many pods of the workload known by `identity` run at once: one for an identity the model does not know.
    pub fn instances_of(&self, identity: &str) -> Instances {
        self.workloads
            .iter()
            .find(|w| w.identity == identity)
            .map_or(Instances::One, |w| w.instances)
    }

    /// The workload named `name`.
    pub fn workload(&self, name: &str) -> Option<&Workload> {
        self.workloads.iter().find(|w| w.workload == name)
    }

    /// Every topic any workload uses, each once.
    pub(crate) fn topic_names(&self) -> BTreeSet<String> {
        self.workloads
            .iter()
            .flat_map(|w| w.topics.iter().map(|t| t.name.clone()))
            .collect()
    }

    /// Every identity the model knows.
    pub(crate) fn identities(&self) -> BTreeSet<&str> {
        self.workloads.iter().map(|w| w.identity.as_str()).collect()
    }
}

/// What a workload's certificates carry of it: its declared and family topics, as `p:pub:` and `p:sub:` names, and its
/// groups, as `g:` names (docs/architecture/policy-enforcement.md, stage 2). Its implied topics are not written: they
/// follow from its identity and its groups. Each once, sorted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertificateNames {
    pub publish: Vec<String>,
    pub subscribe: Vec<String>,
    pub groups: Vec<String>,
    /// The evidence record types its pods' signing certificates may sign, each once, sorted
    /// (docs/architecture/key-custody.md, "Workload signing keys"). Empty until the render computes them from a
    /// collector's scaffold.
    pub records: Vec<String>,
}

impl CertificateNames {
    /// The names as a certificate carries them.
    pub fn san_strings(&self) -> Vec<String> {
        use cert_issuer_common::group::Group;
        use cert_issuer_common::permission::{TopicAccess, TopicPermission};
        let topic = |access, topic: &String| {
            TopicPermission {
                access,
                topic: topic.clone(),
            }
            .to_san_string()
        };
        self.publish
            .iter()
            .map(|t| topic(TopicAccess::Publish, t))
            .chain(
                self.subscribe
                    .iter()
                    .map(|t| topic(TopicAccess::Subscribe, t)),
            )
            .chain(self.groups.iter().map(|g| Group(g.clone()).to_san_string()))
            .collect()
    }

    /// The names a pod's signing certificate carries: each record type, as the evidence capability for that type.
    pub fn signing_san_strings(&self) -> Vec<String> {
        use cert_issuer_common::evidence::EvidenceCapability;
        self.records
            .iter()
            .map(|t| EvidenceCapability::Type(t.clone()).to_san_string())
            .collect()
    }
}

impl Workload {
    /// What this workload's certificates carry.
    pub fn certificate_names(&self) -> CertificateNames {
        let own = |access: polar_topics::Access| -> Vec<String> {
            self.topics
                .iter()
                .filter(|t| {
                    t.access == access && !matches!(t.origin, polar_topics::Origin::Implied { .. })
                })
                .map(|t| t.name.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        CertificateNames {
            publish: own(polar_topics::Access::Publish),
            subscribe: own(polar_topics::Access::Subscribe),
            groups: self
                .groups
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            records: self
                .records
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }
}

impl Model {
    /// What the certificates of the workload known by `identity` carry, when the credentials agent issues it; none for a
    /// workload it does not issue (a bootstrap service is issued by cert-issuer, with cert-issuer's floor) or an identity
    /// the model does not know. Issuance asks this by the identity cert-issuer's validation returns, never by the token's
    /// subject (docs/architecture/authority-model.md, "Decisions": one identity).
    pub fn issued_by_the_credentials_agent(&self, identity: &str) -> Option<CertificateNames> {
        self.workloads
            .iter()
            .find(|w| w.identity == identity && w.issuer == CREDENTIALS_AGENT && !w.bootstrap)
            .map(Workload::certificate_names)
    }
}

/// A person the authority knows (an account in its ledger), for what a change does to them: their identity as Cedar
/// sees it, the groups their certificate carries and the capabilities it holds. A person's identity implies no topics,
/// so only a permit gives them one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub identity: String,
    pub groups: Vec<String>,
    pub capabilities: Vec<Capability>,
}

/// A policy and a groups document, as they stand or as they would: what a judgement is made under. No policy is the
/// floor alone. `memberships` replaces, for Cedar, the groups a certificate carries for each identity it names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pair {
    pub policy: Option<String>,
    pub memberships: BTreeMap<String, Vec<String>>,
    pub hierarchy: Hierarchy,
}

impl Pair {
    /// The pair a deployment's `policy` and `groups` sections make, read as the credentials agent reads them
    /// (`AuthorityBody::of_section`); either may be absent, none yet signed. A person's username stays as it is written:
    /// the account ID it stands for is the ledger's, which a judgement of the sections alone has not, so what it says
    /// is about workloads.
    pub fn from_sections(
        policy: Option<&serde_json::Value>,
        groups: Option<&serde_json::Value>,
    ) -> Result<Pair, String> {
        use credentials_agent_common::authority_update::AuthorityBody;
        let mut pair = Pair::default();
        if let Some(body) = policy {
            match AuthorityBody::of_section("policy", body)? {
                AuthorityBody::Policy { source } => pair.policy = Some(source),
                _ => unreachable!("a policy section reads as a policy"),
            }
        }
        if let Some(body) = groups {
            match AuthorityBody::of_section("groups", body)? {
                AuthorityBody::Groups {
                    memberships,
                    hierarchy,
                } => {
                    pair.memberships = memberships;
                    pair.hierarchy = hierarchy;
                }
                _ => unreachable!("a groups section reads as groups"),
            }
        }
        Ok(pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_pair_is_what_the_policy_and_groups_sections_say_and_neither_is_the_floor() {
        assert_eq!(Pair::from_sections(None, None).unwrap(), Pair::default());
        let pair = Pair::from_sections(
            Some(&json!({ "source": "permit(principal, action, resource);" })),
            Some(&json!({ "memberships": { "a.polar.serviceaccount.cluster.local": ["g"] } })),
        )
        .unwrap();
        assert_eq!(
            pair.policy.as_deref(),
            Some("permit(principal, action, resource);")
        );
        assert_eq!(
            pair.memberships["a.polar.serviceaccount.cluster.local"],
            vec!["g".to_string()]
        );
        assert!(Pair::from_sections(Some(&json!({})), None).is_err());
        assert!(Pair::from_sections(None, Some(&json!({ "groups": {} }))).is_err());
    }

    #[test]
    fn a_model_says_each_workload_s_kind_and_configuration_or_was_rendered_before_it_did() {
        let workload = |extra: serde_json::Value| {
            let mut w = json!({
                "workload": "a", "identity": "a.polar.serviceaccount.cluster.local",
                "issuer": CREDENTIALS_AGENT, "bootstrap": false
            });
            w.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            Model::parse(&json!({ "format": FORMAT, "workloads": [w] }).to_string()).unwrap()
        };
        let now = workload(json!({ "kind": "agent", "config": "document" }));
        assert_eq!(now.workloads[0].kind.as_deref(), Some("agent"));
        assert_eq!(now.workloads[0].config.as_deref(), Some("document"));
        let before = workload(json!({}));
        assert_eq!(
            (
                before.workloads[0].kind.clone(),
                before.workloads[0].config.clone()
            ),
            (None, None)
        );
        assert!(!serde_json::to_string(&before).unwrap().contains("kind"));
    }

    // docs/architecture/key-custody.md, "Workload signing keys": a collector's record types come from the model the render
    // writes, into the names its pods' signing certificates carry; a model written before them reads as none, and one
    // without them is written as it was.
    #[test]
    fn a_workload_s_record_types_are_its_certificates_record_names() {
        let entry = r#"{"workload":"collector","identity":"collector.polar.serviceaccount.cluster.local","issuer":"credentials-agent","bootstrap":false,"records":["mutation","attestation","mutation"]}"#;
        let workload: Workload = serde_json::from_str(entry).unwrap();
        assert_eq!(
            workload.certificate_names().records,
            ["attestation", "mutation"]
        );
        let before = r#"{"workload":"collector","identity":"collector.polar.serviceaccount.cluster.local","issuer":"credentials-agent","bootstrap":false}"#;
        let workload: Workload = serde_json::from_str(before).unwrap();
        assert!(workload.records.is_empty());
        assert!(workload.certificate_names().records.is_empty());
        assert!(
            !serde_json::to_string(&workload)
                .unwrap()
                .contains("records")
        );
    }

    // docs/architecture/key-custody.md, "Workload signing keys": the record types go on the pod's signing certificate,
    // one scoped name a type, and never on its client certificate.
    #[test]
    fn record_types_are_a_signing_certificate_s_names_and_not_a_client_certificate_s() {
        let names = CertificateNames {
            publish: vec!["news".into()],
            records: vec!["attestation".into(), "attestation-report".into()],
            ..CertificateNames::default()
        };
        assert_eq!(names.san_strings(), ["p:pub:news"]);
        assert_eq!(
            names.signing_san_strings(),
            [
                "c:record-evidence:attestation",
                "c:record-evidence:attestation-report"
            ]
        );
        assert!(CertificateNames::default().signing_san_strings().is_empty());
    }

    proptest::proptest! {
        // For every set of record types: the signing names allow exactly those types, and the client names none.
        #[test]
        fn the_signing_names_allow_exactly_the_record_types_and_the_client_names_none(
            records in proptest::collection::btree_set("[a-z0-9-]{1,12}", 0..4),
            groups in proptest::collection::vec("[a-z]{1,6}", 0..3),
        ) {
            use cert_issuer_common::evidence::MayRecord;
            let names = CertificateNames {
                groups,
                records: records.iter().cloned().collect(),
                ..CertificateNames::default()
            };
            let signing = names.signing_san_strings();
            let expected = if records.is_empty() { MayRecord::Nothing } else { MayRecord::Only(records) };
            proptest::prop_assert_eq!(MayRecord::of_names(signing.iter().map(String::as_str)), expected);
            let client = names.san_strings();
            proptest::prop_assert_eq!(MayRecord::of_names(client.iter().map(String::as_str)), MayRecord::Nothing);
        }
    }
}
