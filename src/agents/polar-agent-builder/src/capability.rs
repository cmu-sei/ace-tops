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

//! The capability vocabulary an agent's code can require, shared with the
//! deployment catalog.
//!
//! The names here must equal the keys of `infra/config/capabilities.nuon`
//! (checked in both directions by `names_match_the_deployment_catalog`), so
//! one declaration drives both sides: the catalog says what a deployment
//! provides, and this enum says what the code requires. The deployment
//! publishes what it provides in `POLAR_CAPABILITIES`; `AgentBuilder::build()`
//! compares the two and refuses to start on a mismatch, with a message that
//! names the missing capability.

use crate::protocol::{Access, Location, OperationDecl, Verb};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Environment variable the deployment sets to the comma-separated list of
/// capabilities it provides.
pub const PROVIDED_ENV: &str = crate::environment::CAPABILITIES.name();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// A Cassini client with mTLS. Every agent built by `AgentBuilder`.
    Cassini,
    /// Writes to the graph (Neo4j) over mTLS. The agent's health then depends on the graph.
    GraphWrite,
    /// Reads the graph (Neo4j) over mTLS, with the connection `GraphWrite` has, but its health does not depend on the
    /// graph: a read that fails is answered as unavailable (the state agent, docs/architecture/soft-state.md).
    GraphRead,
    /// Encrypts payloads through CryptoActor. Opt-in.
    Encryption,
    /// Reads the Kubernetes API across the cluster with the workload's own ServiceAccount token: what its cluster
    /// operations declare, its ClusterRole computed from them ([`role_of`]), and never Secrets.
    KubeApiRead,
    /// Reads what runs in Polar's own namespaces (pods and what owns them) with the workload's own ServiceAccount token,
    /// and nothing else in the Kubernetes API: the attestation agent's (docs/architecture/runtime-attestation.md).
    PodRead,
    /// Reads its own soft state back through the state agent (docs/architecture/soft-state.md). Never listed by hand:
    /// the builder adds it for an agent that declares a graph read (`PolarAgent::GRAPH`), and starts its state actor.
    SoftState,
    /// Runs work as Kubernetes Jobs in the build namespace: makes, reads and removes them, reads their pods, logs and
    /// events and the build workload's PodTemplate, and nothing else (docs/architecture/build-orchestrator.md). Never
    /// listed by hand: the builder adds it for an agent whose cluster operations declare a write.
    JobRun,
}

/// What a capability lets an agent do to the Kubernetes API, as its RBAC rules in `capabilities.nuon` say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grants {
    Nothing,
    /// Get, list and watch on anything but Secrets: what `kube-api-read`'s ClusterRole may hold. An agent's secrets
    /// travel escrowed in its signed sections, never through the Kubernetes API.
    ReadAnythingButSecrets,
    /// These, and no more.
    These(&'static [Access]),
}

const fn read(group: &'static str, resource: &'static str) -> [Access; 3] {
    [
        Access::new(Verb::Get, group, resource),
        Access::new(Verb::List, group, resource),
        Access::new(Verb::Watch, group, resource),
    ]
}

/// `pod-read`'s Role, in each attested namespace: get, list and watch on pods and what owns them.
pub const POD_READ_GRANTS: &[Access] = &{
    let [a, b, c] = read("", "pods");
    let [d, e, f] = read("apps", "replicasets");
    let [g, h, i] = read("apps", "deployments");
    let [j, k, l] = read("apps", "statefulsets");
    let [m, n, o] = read("batch", "jobs");
    [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o]
};

/// `job-run`'s Role, in the build namespace alone. No Secret: a build's source comes by digest
/// (docs/architecture/build-orchestrator.md, decision 1).
pub const JOB_RUN_GRANTS: &[Access] = &[
    Access::new(Verb::Create, "batch", "jobs"),
    Access::new(Verb::Get, "batch", "jobs"),
    Access::new(Verb::List, "batch", "jobs"),
    Access::new(Verb::Delete, "batch", "jobs"),
    Access::new(Verb::Get, "", "pods"),
    Access::new(Verb::List, "", "pods"),
    Access::new(Verb::Get, "", "pods/log"),
    Access::new(Verb::List, "", "events"),
    Access::new(Verb::Get, "", "podtemplates"),
];

/// Whether one of `needs` lets an agent do `access` to the Kubernetes API.
pub fn granted(needs: &[Capability], access: &Access) -> bool {
    needs.iter().any(|capability| match capability.grants() {
        Grants::Nothing => false,
        Grants::ReadAnythingButSecrets => !access.verb.writes() && !is_secret(access),
        Grants::These(granted) => granted.contains(access),
    })
}

fn is_secret(access: &Access) -> bool {
    access.group.is_empty() && access.resource == "secrets"
}

/// One rule of a role, as RBAC writes it and the catalog renders it: one group's resource, and the verbs on it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RoleRule {
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<String>,
}

/// The role `capability` gives an agent whose operations are `operations`: what its cluster operations declare that the
/// capability grants, as the verbs RBAC checks for it ([`Verb::uses`]), one rule per resource, the verbs sorted and each
/// once, the rules sorted. What the catalog writes as the RBAC rules, so a role holds what the code declares and no more;
/// empty for a capability that grants nothing.
pub fn role_of(capability: Capability, operations: &[OperationDecl]) -> Vec<RoleRule> {
    let mut by_resource: BTreeMap<(&str, &str), std::collections::BTreeSet<&str>> = BTreeMap::new();
    for operation in operations {
        let Location::Cluster { access, .. } = operation.location else {
            continue;
        };
        for wanted in access.iter().filter(|a| granted(&[capability], a)) {
            by_resource
                .entry((wanted.group, wanted.resource))
                .or_default()
                .extend(wanted.verb.uses().iter().map(|v| v.as_str()));
        }
    }
    by_resource
        .into_iter()
        .map(|((group, resource), verbs)| RoleRule {
            api_groups: vec![group.to_string()],
            resources: vec![resource.to_string()],
            verbs: verbs.into_iter().map(str::to_string).collect(),
        })
        .collect()
}

/// Each role `needs` gives an agent whose operations are `operations`, by the capability's name: the ones that hold
/// something.
pub fn roles_of(
    needs: &[Capability],
    operations: &[OperationDecl],
) -> BTreeMap<String, Vec<RoleRule>> {
    needs
        .iter()
        .map(|c| (c.as_str().to_string(), role_of(*c, operations)))
        .filter(|(_, role)| !role.is_empty())
        .collect()
}

impl Capability {
    /// Every capability, in the order the catalog lists them.
    pub const ALL: [Capability; 8] = [
        Capability::Cassini,
        Capability::GraphWrite,
        Capability::GraphRead,
        Capability::Encryption,
        Capability::KubeApiRead,
        Capability::PodRead,
        Capability::SoftState,
        Capability::JobRun,
    ];

    /// What it lets an agent do to the Kubernetes API.
    pub const fn grants(self) -> Grants {
        match self {
            Capability::KubeApiRead => Grants::ReadAnythingButSecrets,
            Capability::PodRead => Grants::These(POD_READ_GRANTS),
            Capability::JobRun => Grants::These(JOB_RUN_GRANTS),
            _ => Grants::Nothing,
        }
    }

    /// The capability a name in `POLAR_CAPABILITIES` stands for, if this code knows it.
    pub fn from_name(name: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.as_str() == name)
    }

    /// The known capabilities in a comma-separated `POLAR_CAPABILITIES` value. Names this
    /// code does not know are ignored, as in [`check`].
    pub fn parse_list(raw: &str) -> Vec<Capability> {
        raw.split(',')
            .map(str::trim)
            .filter_map(Capability::from_name)
            .collect()
    }

    /// The name used in `capabilities.nuon` and in `POLAR_CAPABILITIES`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Cassini => "cassini",
            Capability::GraphWrite => "graph-write",
            Capability::GraphRead => "graph-read",
            Capability::Encryption => "encryption",
            Capability::KubeApiRead => "kube-api-read",
            Capability::PodRead => "pod-read",
            Capability::SoftState => "soft-state",
            Capability::JobRun => "job-run",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of comparing what the code requires with what the deployment
/// says it provides.
#[derive(Debug, PartialEq, Eq)]
pub enum CapabilityCheck {
    /// Every required capability is provided.
    Satisfied,
    /// The deployment did not say what it provides (`POLAR_CAPABILITIES` is
    /// unset), for example a run outside the catalog. Nothing can be checked.
    NotDeclared,
    /// These required capabilities are not provided.
    Missing(Vec<Capability>),
}

/// Compares `required` with the deployment's comma-separated `provided`
/// list. Names in `provided` this code does not know are ignored: a
/// deployment may provide more than one agent needs.
pub fn check(required: &[Capability], provided: Option<&str>) -> CapabilityCheck {
    let Some(provided) = provided else {
        return CapabilityCheck::NotDeclared;
    };
    let provided: Vec<&str> = provided
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let mut missing = Vec::new();
    for c in required {
        if !provided.contains(&c.as_str()) && !missing.contains(c) {
            missing.push(*c);
        }
    }

    if missing.is_empty() {
        CapabilityCheck::Satisfied
    } else {
        CapabilityCheck::Missing(missing)
    }
}

/// The message `build()` fails with when capabilities are missing.
pub fn missing_message(missing: &[Capability], provided: Option<&str>) -> String {
    let names: Vec<&str> = missing.iter().map(|c| c.as_str()).collect();
    format!(
        "this agent requires capabilit{} {} but the deployment provides: [{}] \
         ({PROVIDED_ENV}). Add the missing capabilit{} to the workload's `needs` in \
         infra/config/workloads, or stop requiring {} in the agent.",
        if names.len() == 1 { "y" } else { "ies" },
        names.join(", "),
        provided.unwrap_or(""),
        if names.len() == 1 { "y" } else { "ies" },
        if names.len() == 1 { "it" } else { "them" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn names_map_to_capabilities_and_unknown_ones_are_ignored() {
        assert_eq!(
            Capability::parse_list(" cassini, graph-write ,nonsense,,"),
            [Capability::Cassini, Capability::GraphWrite]
        );
        assert_eq!(
            Capability::from_name("encryption"),
            Some(Capability::Encryption)
        );
        assert_eq!(Capability::from_name("Cassini"), None);
    }

    #[test]
    fn satisfied_when_every_requirement_is_provided() {
        let r = check(
            &[Capability::Cassini, Capability::GraphWrite],
            Some("cassini,graph-write,encryption"),
        );
        assert_eq!(r, CapabilityCheck::Satisfied);
    }

    #[test]
    fn a_deployment_may_provide_more_than_the_code_requires() {
        let r = check(
            &[Capability::Cassini],
            Some("cassini,graph-write,future-thing"),
        );
        assert_eq!(r, CapabilityCheck::Satisfied);
    }

    #[test]
    fn missing_lists_exactly_what_is_not_provided() {
        let r = check(
            &[
                Capability::Cassini,
                Capability::GraphWrite,
                Capability::Encryption,
            ],
            Some("cassini"),
        );
        assert_eq!(
            r,
            CapabilityCheck::Missing(vec![Capability::GraphWrite, Capability::Encryption])
        );
    }

    #[test]
    fn whitespace_and_empty_entries_are_tolerated() {
        let r = check(&[Capability::Cassini], Some(" cassini , ,graph-write "));
        assert_eq!(r, CapabilityCheck::Satisfied);
    }

    #[test]
    fn an_empty_list_provides_nothing() {
        let r = check(&[Capability::Cassini], Some(""));
        assert_eq!(r, CapabilityCheck::Missing(vec![Capability::Cassini]));
    }

    #[test]
    fn an_undeclared_deployment_cannot_be_checked() {
        assert_eq!(
            check(&[Capability::Cassini], None),
            CapabilityCheck::NotDeclared
        );
    }

    #[test]
    fn duplicate_requirements_are_reported_once() {
        let r = check(
            &[Capability::Encryption, Capability::Encryption],
            Some("cassini"),
        );
        assert_eq!(r, CapabilityCheck::Missing(vec![Capability::Encryption]));
    }

    #[test]
    fn the_message_names_the_missing_capability() {
        let m = missing_message(&[Capability::GraphWrite], Some("cassini"));
        assert!(m.contains("graph-write"), "{m}");
        assert!(m.contains("cassini"), "{m}");
        assert!(m.contains(PROVIDED_ENV), "{m}");
    }

    /// Top-level keys of `infra/config/capabilities.nuon`: lines indented by
    /// exactly two spaces that read `name: {`.
    fn catalog_keys(nuon: &str) -> Vec<String> {
        nuon.lines()
            .filter(|l| l.starts_with("  ") && !l.starts_with("   "))
            .filter_map(|l| l.trim_end().strip_suffix(": {"))
            .map(|k| k.trim().to_string())
            .filter(|k| {
                !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
            .collect()
    }

    /// Capabilities the catalog gives a deployment that no code ever requires: the shape of the
    /// pod (a persistent volume, a pinned CA, a server certificate, the CA cert-issuer signs with),
    /// not something the agent's own health depends on. They are in `POLAR_CAPABILITIES`, which
    /// ignores names the code does not know.
    const DEPLOYMENT_ONLY: &[&str] = &[
        "cassini-server",
        "deployment-ca",
        "deployment-copy",
        "git-server",
        "persistent-data",
        "pinned-ca",
        "provisioned-ca",
        "tracing",
        "working-checkout",
    ];

    #[test]
    fn names_match_the_deployment_catalog() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../infra/config/capabilities.nuon");
        // Built from a source tree that does not include infra/ (a filtered
        // nix source, a published crate): nothing to compare against.
        let Ok(nuon) = std::fs::read_to_string(&path) else {
            eprintln!("skipping: {} not found", path.display());
            return;
        };

        let mut in_catalog = catalog_keys(&nuon);
        for name in DEPLOYMENT_ONLY {
            assert!(
                in_catalog.iter().any(|k| k == name),
                "{name} is listed as deployment-only but the catalog has no such capability"
            );
        }
        in_catalog.retain(|k| !DEPLOYMENT_ONLY.contains(&k.as_str()));
        let mut in_code: Vec<String> = Capability::ALL
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        in_catalog.sort();
        in_code.sort();

        assert_eq!(
            in_code, in_catalog,
            "polar_agent_builder::Capability and infra/config/capabilities.nuon must list the \
             same capabilities: add the missing one on the side that lacks it"
        );
    }

    #[test]
    fn the_key_parser_ignores_nested_and_commented_lines() {
        let nuon = "# header\n{\n  # a comment: {\n  alpha: {\n    pod: {\n    }\n  }\n  beta-two: {\n  }\n}\n";
        assert_eq!(
            catalog_keys(nuon),
            vec!["alpha".to_string(), "beta-two".to_string()]
        );
    }

    use crate::protocol::ProtocolKind;
    use proptest::prelude::*;

    fn cluster(access: &'static [Access]) -> OperationDecl {
        OperationDecl {
            name: "op",
            doc: "",
            protocol: ProtocolKind::KUBERNETES,
            location: Location::Cluster {
                access,
                namespace: None,
            },
        }
    }

    fn rule(group: &str, resource: &str, verbs: &[&str]) -> RoleRule {
        RoleRule {
            api_groups: vec![group.to_string()],
            resources: vec![resource.to_string()],
            verbs: verbs.iter().map(|v| v.to_string()).collect(),
        }
    }

    #[test]
    fn kube_api_read_reads_anything_but_secrets() {
        assert!(granted(
            &[Capability::KubeApiRead],
            &Access::new(Verb::Watch, "apps", "deployments")
        ));
        for verb in [Verb::Get, Verb::List, Verb::Watch] {
            assert!(!granted(
                &[Capability::KubeApiRead],
                &Access::new(verb, "", "secrets")
            ));
        }
        assert!(!granted(
            &[Capability::KubeApiRead],
            &Access::new(Verb::Create, "batch", "jobs")
        ));
    }

    #[test]
    fn a_role_is_what_the_operations_declare_and_a_watch_lists_first() {
        const WATCHES: &[Access] = &[
            Access::new(Verb::Watch, "", "pods"),
            Access::new(Verb::Watch, "apps", "deployments"),
        ];
        const IDENTIFIES: &[Access] = &[
            Access::new(Verb::Get, "", "namespaces"),
            Access::new(Verb::Watch, "", "pods"),
        ];
        let role = role_of(
            Capability::KubeApiRead,
            &[cluster(WATCHES), cluster(IDENTIFIES)],
        );
        assert_eq!(
            role,
            [
                rule("", "namespaces", &["get"]),
                rule("", "pods", &["list", "watch"]),
                rule("apps", "deployments", &["list", "watch"]),
            ]
        );
    }

    #[test]
    fn a_role_holds_only_what_its_capability_grants() {
        const BOTH: &[Access] = &[
            Access::new(Verb::Create, "batch", "jobs"),
            Access::new(Verb::Watch, "", "pods"),
        ];
        let operations = [cluster(BOTH)];
        assert_eq!(
            role_of(Capability::JobRun, &operations),
            [rule("batch", "jobs", &["create"])]
        );
        assert_eq!(
            role_of(Capability::KubeApiRead, &operations),
            [rule("", "pods", &["list", "watch"])]
        );
        assert!(role_of(Capability::GraphWrite, &operations).is_empty());
        assert!(role_of(Capability::KubeApiRead, &[]).is_empty());
    }

    /// The accesses a declaration draws from: reads, writes and Secrets, in a few groups.
    const ACCESSES: [Access; 10] = [
        Access::new(Verb::Watch, "", "pods"),
        Access::new(Verb::List, "", "pods"),
        Access::new(Verb::Get, "", "pods"),
        Access::new(Verb::Watch, "apps", "deployments"),
        Access::new(Verb::Get, "", "namespaces"),
        Access::new(Verb::Get, "", "secrets"),
        Access::new(Verb::Watch, "", "secrets"),
        Access::new(Verb::Create, "batch", "jobs"),
        Access::new(Verb::Delete, "batch", "jobs"),
        Access::new(Verb::Get, "", "pods/log"),
    ];

    fn declared(accesses: &[Vec<Access>]) -> Vec<OperationDecl> {
        accesses
            .iter()
            .map(|a| cluster(Box::leak(a.clone().into_boxed_slice())))
            .collect()
    }

    /// What a role allows, one (group, resource, verb) at a time.
    fn allows(role: &[RoleRule]) -> std::collections::BTreeSet<(String, String, String)> {
        role.iter()
            .flat_map(|r| {
                r.verbs
                    .iter()
                    .map(|v| (r.api_groups[0].clone(), r.resources[0].clone(), v.clone()))
            })
            .collect()
    }

    proptest! {
        /// A role allows exactly the RBAC verbs of what the operations declare and the capability grants, nothing
        /// else: one rule per resource, its verbs sorted and each once, the rules sorted, whatever order the operations
        /// come in. So no role holds a Secret, none holds a write its capability does not grant, and none misses the
        /// list a declared watch makes.
        #[test]
        fn a_role_allows_exactly_what_is_declared_and_granted(
            capability in proptest::sample::select(Capability::ALL.to_vec()),
            accesses in proptest::collection::vec(
                proptest::collection::vec(proptest::sample::select(ACCESSES.to_vec()), 1..4),
                0..4,
            ),
        ) {
            let role = role_of(capability, &declared(&accesses));
            let mut expected = std::collections::BTreeSet::new();
            for access in accesses.iter().flatten().filter(|a| granted(&[capability], a)) {
                for verb in access.verb.uses() {
                    expected.insert((access.group.to_string(), access.resource.to_string(), verb.as_str().to_string()));
                }
            }
            prop_assert_eq!(allows(&role), expected);
            for r in &role {
                prop_assert_eq!(r.api_groups.len(), 1);
                prop_assert_eq!(r.resources.len(), 1);
                let mut verbs = r.verbs.clone();
                verbs.sort();
                verbs.dedup();
                prop_assert_eq!(&verbs, &r.verbs);
                prop_assert!(!access_is_secret(&r.api_groups[0], &r.resources[0]), "{:?}", role);
            }
            let mut sorted = role.clone();
            sorted.sort();
            sorted.dedup_by(|a, b| a.api_groups == b.api_groups && a.resources == b.resources);
            prop_assert_eq!(&sorted, &role);

            let mut reversed = accesses.clone();
            reversed.reverse();
            for each in &mut reversed {
                each.reverse();
            }
            prop_assert_eq!(role_of(capability, &declared(&reversed)), role);
        }
    }

    fn access_is_secret(group: &str, resource: &str) -> bool {
        group.is_empty() && resource == "secrets"
    }
}
