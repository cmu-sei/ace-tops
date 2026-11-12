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

//! What an agent may ask for, and whether a request is allowed: the one decision every request of the domain's passes
//! through (docs/architecture/protocol-handlers.md, "The judgment"). Pure, so that a rule holds for every input.

/// A protocol a handler exists for. An operation says which it is for, and the builder starts those at load, each through
/// what is said here. So a protocol's code, and any library under it, is linked only into an agent that names it in an
/// operation: libgit2 is in the git observer and in nothing else.
#[derive(Clone, Copy)]
pub struct ProtocolKind {
    name: &'static str,
    goes_out: bool,
    to_the_cluster: bool,
    pub(crate) start: super::Starter,
    /// How it makes the egress probe's request, for a protocol that goes out (`--probe-egress`, [`super::probe`]).
    probe: Option<super::probe::Prober>,
}

impl ProtocolKind {
    pub const HTTP: Self = Self {
        name: "http",
        goes_out: true,
        to_the_cluster: false,
        start: super::http::start,
        probe: Some(super::http::probe),
    };
    pub const GIT: Self = Self {
        name: "git",
        goes_out: true,
        to_the_cluster: false,
        start: super::git::start,
        probe: Some(super::git::probe),
    };
    /// The Kubernetes API of the cluster the pod runs in, which goes no further than that cluster.
    pub const KUBERNETES: Self = Self {
        name: "kubernetes",
        goes_out: false,
        to_the_cluster: true,
        start: super::kubernetes::start,
        probe: None,
    };
    /// Only in this crate's tests, for the framework alone.
    #[cfg(test)]
    pub const TEST: Self = Self {
        name: "test",
        goes_out: false,
        to_the_cluster: false,
        start: super::tests::start_test_protocol,
        probe: None,
    };

    pub const fn as_str(self) -> &'static str {
        self.name
    }

    /// Whether it reaches outside the cluster, and so goes out as the egress section says.
    pub(crate) const fn goes_out(self) -> bool {
        self.goes_out
    }

    /// How it makes the egress probe's request, if it goes out and is probed.
    pub(crate) const fn prober(self) -> Option<super::probe::Prober> {
        self.probe
    }

    /// Whether it goes to [`Location::Cluster`], and nowhere else. Asked of the kind and not by comparing with one: naming a kind in
    /// code every agent runs would link its library into every agent.
    pub(crate) const fn to_the_cluster(self) -> bool {
        self.to_the_cluster
    }
}

impl PartialEq for ProtocolKind {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for ProtocolKind {}

impl std::fmt::Debug for ProtocolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}

/// Which credential a request uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// The one with this name: an entry of the agent's `credentials` section.
    Named(&'static str),
    /// One the request names ([`super::Operation::credential`]), as a repository's configuration names its own.
    Chosen,
    /// The one whose signed binding names the host the request goes to, as a registry learned from an image is: only with
    /// [`Location::Bound`]. Nobody names it, the binding decides, and it stays the same one wherever the request goes next.
    ForHost,
}

/// Where a request may go. An arbitrary request has no credential to name: the two cannot be declared together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// To the host of this variable, the agent's own configuration, read as it is in force when the request is made.
    Configured {
        variable: &'static str,
        credential: Option<Credential>,
    },
    /// To a host the domain learned at run time, which the credential's signed binding must name: someone signed that
    /// host off. The CryptoActor checks the binding, where the secret is.
    Bound { credential: Credential },
    /// To any host: a permission the agent declares for a request not known ahead of time. Always without a credential,
    /// and marked in the record of each request (the maintainer, 2026-11-03).
    Arbitrary,
    /// To the Kubernetes API of the cluster the pod runs in, where Kubernetes tells every pod it is. It goes with the pod's
    /// service account token, which no signed section holds and the protocol's client reads for itself: the capability
    /// declares it, and Kubernetes is the trust base. It may do what `access` says and nothing else (the maintainer,
    /// 2026-11-07: a cluster operation's declaration binds what it may do), so a watch cannot delete, and what it may do
    /// is what the capability is computed from.
    ///
    /// `namespace` says where: the key, in the cluster's namespaces (`cluster.namespaces`), of the one namespace it acts
    /// in, such as `builds`, and a request in any other is refused; or `None` for an operation not held to one namespace
    /// (an object across the cluster, a watch across it, or the namespaces its capability's Roles are placed in).
    Cluster {
        access: &'static [Access],
        namespace: Option<&'static str>,
    },
}

/// What a request does to the Kubernetes API, as RBAC names it: a verb on a group's resource (`""` for the core group;
/// a subresource such as `pods/log` by its path). Plain data, so that naming it links nothing of Kubernetes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Access {
    pub verb: Verb,
    pub group: &'static str,
    pub resource: &'static str,
}

/// A verb of the Kubernetes API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verb {
    Get,
    List,
    Watch,
    Create,
    Delete,
}

impl Verb {
    /// As RBAC writes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Verb::Get => "get",
            Verb::List => "list",
            Verb::Watch => "watch",
            Verb::Create => "create",
            Verb::Delete => "delete",
        }
    }

    /// Whether it changes what is in the cluster.
    pub const fn writes(self) -> bool {
        matches!(self, Verb::Create | Verb::Delete)
    }

    /// The verbs RBAC checks when the handler does this: a watch lists first (`kube`'s watcher, in
    /// `protocol/kubernetes.rs`), and every other verb is itself.
    pub const fn uses(self) -> &'static [Verb] {
        match self {
            Verb::Watch => &[Verb::List, Verb::Watch],
            Verb::Get => &[Verb::Get],
            Verb::List => &[Verb::List],
            Verb::Create => &[Verb::Create],
            Verb::Delete => &[Verb::Delete],
        }
    }
}

impl Access {
    pub const fn new(verb: Verb, group: &'static str, resource: &'static str) -> Self {
        Self {
            verb,
            group,
            resource,
        }
    }
}

impl std::fmt::Display for Access {
    /// `watch pods`, `create batch/jobs`: the verb, then the group's resource.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.group.is_empty() {
            write!(f, "{} {}", self.verb.as_str(), self.resource)
        } else {
            write!(f, "{} {}/{}", self.verb.as_str(), self.group, self.resource)
        }
    }
}

/// An operation as the agent declares it (`PolarAgent::OPERATIONS`): what the scaffold prints and the catalog carries, so
/// applying the catalog is the sign-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationDecl {
    /// Unique among the agent's operations.
    pub name: &'static str,
    /// What it is for, in a sentence.
    pub doc: &'static str,
    pub protocol: ProtocolKind,
    pub location: Location,
}

/// Where a request would go, and what it would do, as its protocol reads it from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    /// Whether the connection is encrypted: a credential goes over no other.
    pub encrypted: bool,
    /// What a request to the Kubernetes API does; `None` for any other protocol.
    pub access: Option<Access>,
    /// What an object the request would create gives a pod of its node, each way out of a container by its name
    /// (`privileged`, `hostNetwork`, `hostPath`...): empty for anything else (`kubernetes::reaches_node`).
    pub reaches_node: Vec<&'static str>,
    /// The namespace a request to the Kubernetes API acts in, by the cluster's name for it: `None` for one that acts in
    /// none (an object across the cluster, a watch across it), and for any other protocol.
    pub namespace: Option<String>,
}

/// Why a request is not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    #[error("the agent does not declare this operation")]
    Undeclared,
    #[error("the variable it goes to is not set")]
    NotConfigured,
    #[error("it goes to a host other than the one configured")]
    OffTheConfiguredHost,
    #[error("a credential goes only over an encrypted connection")]
    NotEncrypted,
    #[error("the request names no credential, and the operation needs one")]
    NoCredentialNamed,
    #[error("no credential is bound to this host")]
    NoCredentialBound,
    #[error("the operation does not declare what the request would do to the cluster")]
    AccessUndeclared,
    /// No Polar agent makes a pod that reaches its node, whatever it declares (docs/architecture/build-orchestrator.md, 5d).
    #[error("the object would run a pod with access to its node")]
    ReachesTheNode,
    /// The operation names a namespace by its key, and the deployment does not say the cluster's name for it
    /// (`POLAR_CLUSTER_NAMESPACES`).
    #[error("the operation names a namespace the deployment does not name")]
    NamespaceUnknown,
    /// The operation names one namespace, and the request acts in another, or in none.
    #[error("it acts outside the namespace its operation names")]
    OutsideTheNamespace,
}

/// What [`judge`] decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed, with the credential to ask the CryptoActor for, if any.
    Allow {
        credential: Option<String>,
    },
    Deny(Denial),
}

/// Whether `operation` may go to `target`. `declared` is what the agent declared; `configured` is what the operation's
/// location names, as it is in force: for a configured operation the host of its variable, if it is set, and for a cluster
/// operation that names a namespace the cluster's name for it, if the deployment says it; `chosen` is the credential the
/// request names, or for [`Credential::ForHost`] the one bound to the host it first goes to.
pub fn judge(
    operation: &OperationDecl,
    declared: &[OperationDecl],
    target: &Target,
    configured: Option<&str>,
    chosen: Option<&str>,
) -> Verdict {
    if !declared.contains(operation) {
        return Verdict::Deny(Denial::Undeclared);
    }
    let credential = match operation.location {
        Location::Configured {
            credential,
            variable: _,
        } => {
            let Some(configured) = configured else {
                return Verdict::Deny(Denial::NotConfigured);
            };
            if !target.host.eq_ignore_ascii_case(configured) {
                return Verdict::Deny(Denial::OffTheConfiguredHost);
            }
            credential
        }
        Location::Bound { credential } => Some(credential),
        Location::Arbitrary => None,
        // It names nothing for the CryptoActor to give, and the token goes with it all the same.
        Location::Cluster { access, namespace } => {
            if !target.encrypted {
                return Verdict::Deny(Denial::NotEncrypted);
            }
            if !target.access.is_some_and(|wanted| access.contains(&wanted)) {
                return Verdict::Deny(Denial::AccessUndeclared);
            }
            // An operation held to one namespace acts there and nowhere else: not in another, and not across the cluster.
            if namespace.is_some() {
                let Some(name) = configured else {
                    return Verdict::Deny(Denial::NamespaceUnknown);
                };
                if target.namespace.as_deref() != Some(name) {
                    return Verdict::Deny(Denial::OutsideTheNamespace);
                }
            }
            if !target.reaches_node.is_empty() {
                return Verdict::Deny(Denial::ReachesTheNode);
            }
            None
        }
    };
    let credential = match credential {
        None => None,
        Some(Credential::Named(name)) => Some(name.to_string()),
        Some(Credential::Chosen) => match chosen {
            Some(name) => Some(name.to_string()),
            None => return Verdict::Deny(Denial::NoCredentialNamed),
        },
        Some(Credential::ForHost) => match chosen {
            Some(name) => Some(name.to_string()),
            None => return Verdict::Deny(Denial::NoCredentialBound),
        },
    };
    if credential.is_some() && !target.encrypted {
        return Verdict::Deny(Denial::NotEncrypted);
    }
    Verdict::Allow { credential }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const fn declared(location: Location) -> OperationDecl {
        OperationDecl {
            name: "an-operation",
            doc: "",
            protocol: ProtocolKind::TEST,
            location,
        }
    }

    fn target(host: &str, encrypted: bool) -> Target {
        Target {
            host: host.to_string(),
            encrypted,
            access: None,
            reaches_node: Vec::new(),
            namespace: None,
        }
    }

    const WATCH_PODS: Access = Access::new(Verb::Watch, "", "pods");
    const CREATE_JOBS: Access = Access::new(Verb::Create, "batch", "jobs");

    fn to_the_cluster(encrypted: bool, access: Option<Access>) -> Target {
        Target {
            access,
            ..target("10.96.0.1", encrypted)
        }
    }

    fn allowed(credential: Option<&str>) -> Verdict {
        Verdict::Allow {
            credential: credential.map(str::to_string),
        }
    }

    const CONFIGURED: OperationDecl = declared(Location::Configured {
        variable: "SITE_URL",
        credential: Some(Credential::Named("site")),
    });

    #[test]
    fn a_configured_request_goes_to_its_host_with_its_credential() {
        let site = target("site.example.org", true);
        assert_eq!(
            judge(
                &CONFIGURED,
                &[CONFIGURED],
                &site,
                Some("site.example.org"),
                None
            ),
            allowed(Some("site"))
        );
        // Host names are compared as DNS compares them.
        assert_eq!(
            judge(
                &CONFIGURED,
                &[CONFIGURED],
                &site,
                Some("SITE.example.org"),
                None
            ),
            allowed(Some("site"))
        );
    }

    #[test]
    fn a_configured_request_goes_nowhere_else_and_not_when_nothing_is_set() {
        let elsewhere = target("elsewhere.example.org", true);
        assert_eq!(
            judge(
                &CONFIGURED,
                &[CONFIGURED],
                &elsewhere,
                Some("site.example.org"),
                None
            ),
            Verdict::Deny(Denial::OffTheConfiguredHost)
        );
        assert_eq!(
            judge(&CONFIGURED, &[CONFIGURED], &elsewhere, None, None),
            Verdict::Deny(Denial::NotConfigured)
        );
    }

    #[test]
    fn a_configured_request_with_no_credential_may_go_unencrypted() {
        const OPEN: OperationDecl = declared(Location::Configured {
            variable: "SITE_URL",
            credential: None,
        });
        let site = target("site.svc", false);
        assert_eq!(
            judge(&OPEN, &[OPEN], &site, Some("site.svc"), None),
            allowed(None)
        );
    }

    #[test]
    fn a_credential_goes_over_no_connection_that_is_not_encrypted() {
        let site = target("site.example.org", false);
        assert_eq!(
            judge(
                &CONFIGURED,
                &[CONFIGURED],
                &site,
                Some("site.example.org"),
                None
            ),
            Verdict::Deny(Denial::NotEncrypted)
        );
    }

    #[test]
    fn a_request_learned_at_run_time_uses_the_credential_it_names_or_the_one_declared() {
        const CHOSEN: OperationDecl = declared(Location::Bound {
            credential: Credential::Chosen,
        });
        const NAMED: OperationDecl = declared(Location::Bound {
            credential: Credential::Named("registry"),
        });
        let host = target("learned.example.org", true);
        assert_eq!(
            judge(&CHOSEN, &[CHOSEN], &host, None, Some("github")),
            allowed(Some("github"))
        );
        assert_eq!(
            judge(&CHOSEN, &[CHOSEN], &host, None, None),
            Verdict::Deny(Denial::NoCredentialNamed)
        );
        // What the operation declared wins over anything the request says.
        assert_eq!(
            judge(&NAMED, &[NAMED], &host, None, Some("other")),
            allowed(Some("registry"))
        );
    }

    #[test]
    fn a_request_for_the_credential_bound_to_its_host_needs_one_to_be() {
        const FOR_HOST: OperationDecl = declared(Location::Bound {
            credential: Credential::ForHost,
        });
        let host = target("reg.example.org", true);
        assert_eq!(
            judge(&FOR_HOST, &[FOR_HOST], &host, None, Some("registry")),
            allowed(Some("registry"))
        );
        assert_eq!(
            judge(&FOR_HOST, &[FOR_HOST], &host, None, None),
            Verdict::Deny(Denial::NoCredentialBound)
        );
        assert_eq!(
            judge(
                &FOR_HOST,
                &[FOR_HOST],
                &target("reg.example.org", false),
                None,
                Some("registry")
            ),
            Verdict::Deny(Denial::NotEncrypted)
        );
    }

    #[test]
    fn an_operation_the_agent_did_not_declare_is_denied() {
        let site = target("site.example.org", true);
        assert_eq!(
            judge(&CONFIGURED, &[], &site, Some("site.example.org"), None),
            Verdict::Deny(Denial::Undeclared)
        );
        // Declaring the name is not enough: it must be declared as it is asked for.
        const SAME_NAME_ARBITRARY: OperationDecl = declared(Location::Arbitrary);
        assert_eq!(
            judge(&SAME_NAME_ARBITRARY, &[CONFIGURED], &site, None, None),
            Verdict::Deny(Denial::Undeclared)
        );
    }

    #[test]
    fn a_request_to_the_cluster_names_no_credential_and_goes_only_encrypted() {
        const CLUSTER: OperationDecl = declared(Location::Cluster {
            access: &[WATCH_PODS],
            namespace: None,
        });
        assert_eq!(
            judge(
                &CLUSTER,
                &[CLUSTER],
                &to_the_cluster(true, Some(WATCH_PODS)),
                None,
                Some("site")
            ),
            allowed(None)
        );
        assert_eq!(
            judge(
                &CLUSTER,
                &[CLUSTER],
                &to_the_cluster(false, Some(WATCH_PODS)),
                None,
                None
            ),
            Verdict::Deny(Denial::NotEncrypted)
        );
    }

    /// A cluster request may do what its operation declares and nothing else: a watch of pods cannot list them, let
    /// alone create a Job, and a request that says nothing of what it does is not allowed.
    #[test]
    fn a_cluster_request_may_do_only_what_its_operation_declares() {
        const WATCHING: OperationDecl = declared(Location::Cluster {
            access: &[WATCH_PODS],
            namespace: None,
        });
        for wanted in [
            Some(Access::new(Verb::List, "", "pods")),
            Some(Access::new(Verb::Watch, "", "secrets")),
            Some(Access::new(Verb::Watch, "apps", "pods")),
            Some(CREATE_JOBS),
            None,
        ] {
            assert_eq!(
                judge(
                    &WATCHING,
                    &[WATCHING],
                    &to_the_cluster(true, wanted),
                    None,
                    None
                ),
                Verdict::Deny(Denial::AccessUndeclared),
                "{wanted:?}"
            );
        }
        assert_eq!(CREATE_JOBS.to_string(), "create batch/jobs");
        assert_eq!(WATCH_PODS.to_string(), "watch pods");
    }

    /// docs/architecture/build-orchestrator.md, 5d and O2c: no Polar agent makes a pod that reaches its node, whatever
    /// its operation declares; one that asks nothing of the node is judged as before.
    #[test]
    fn a_create_that_would_reach_the_node_is_denied_whatever_is_declared() {
        const CREATING: OperationDecl = declared(Location::Cluster {
            access: &[CREATE_JOBS],
            namespace: None,
        });
        let creating = |reaches_node: Vec<&'static str>| Target {
            reaches_node,
            ..to_the_cluster(true, Some(CREATE_JOBS))
        };
        assert_eq!(
            judge(&CREATING, &[CREATING], &creating(Vec::new()), None, None),
            allowed(None)
        );
        for ways in [
            vec!["privileged"],
            vec!["hostNetwork", "hostPath"],
            vec!["unconfined"],
        ] {
            assert_eq!(
                judge(&CREATING, &[CREATING], &creating(ways.clone()), None, None),
                Verdict::Deny(Denial::ReachesTheNode),
                "{ways:?}"
            );
        }
    }

    /// A cluster operation that names a namespace acts there and nowhere else: a request in another namespace, or across
    /// the cluster, is refused, and so is any request of it while the deployment does not say the cluster's name for the
    /// key. One that names none is judged as before, wherever its request acts.
    #[test]
    fn a_cluster_request_acts_only_in_the_namespace_its_operation_names() {
        const IN_BUILDS: OperationDecl = declared(Location::Cluster {
            access: &[CREATE_JOBS],
            namespace: Some("builds"),
        });
        let in_namespace = |namespace: Option<&str>| Target {
            namespace: namespace.map(str::to_string),
            ..to_the_cluster(true, Some(CREATE_JOBS))
        };
        assert_eq!(
            judge(
                &IN_BUILDS,
                &[IN_BUILDS],
                &in_namespace(Some("polar-builds")),
                Some("polar-builds"),
                None
            ),
            allowed(None)
        );
        for elsewhere in [Some("kube-system"), Some("builds"), None] {
            assert_eq!(
                judge(
                    &IN_BUILDS,
                    &[IN_BUILDS],
                    &in_namespace(elsewhere),
                    Some("polar-builds"),
                    None
                ),
                Verdict::Deny(Denial::OutsideTheNamespace),
                "{elsewhere:?}"
            );
        }
        assert_eq!(
            judge(
                &IN_BUILDS,
                &[IN_BUILDS],
                &in_namespace(Some("polar-builds")),
                None,
                None
            ),
            Verdict::Deny(Denial::NamespaceUnknown)
        );
        const ANYWHERE: OperationDecl = declared(Location::Cluster {
            access: &[CREATE_JOBS],
            namespace: None,
        });
        for anywhere in [Some("kube-system"), None] {
            assert_eq!(
                judge(&ANYWHERE, &[ANYWHERE], &in_namespace(anywhere), None, None),
                allowed(None),
                "{anywhere:?}"
            );
        }
        // Held to its namespace is not a way round anything else: the node and what is declared are judged as before.
        assert_eq!(
            judge(
                &IN_BUILDS,
                &[IN_BUILDS],
                &Target {
                    reaches_node: vec!["privileged"],
                    ..in_namespace(Some("polar-builds"))
                },
                Some("polar-builds"),
                None
            ),
            Verdict::Deny(Denial::ReachesTheNode)
        );
    }

    fn credential() -> impl Strategy<Value = Credential> {
        prop_oneof![
            Just(Credential::Named("site")),
            Just(Credential::Chosen),
            Just(Credential::ForHost)
        ]
    }

    fn location() -> impl Strategy<Value = Location> {
        prop_oneof![
            proptest::option::of(credential()).prop_map(|credential| Location::Configured {
                variable: "SITE_URL",
                credential,
            }),
            credential().prop_map(|credential| Location::Bound { credential }),
            Just(Location::Arbitrary),
            Just(Location::Cluster {
                access: &[WATCH_PODS],
                namespace: None,
            }),
        ]
    }

    /// The accesses a declaration and a request draw from.
    const UNIVERSE: [Access; 6] = [
        WATCH_PODS,
        Access::new(Verb::List, "", "pods"),
        Access::new(Verb::Get, "", "pods/log"),
        CREATE_JOBS,
        Access::new(Verb::Delete, "batch", "jobs"),
        Access::new(Verb::List, "", "events"),
    ];

    /// Every declaration a subset of the universe can be, as static slices, since a declaration is static.
    fn declarations() -> &'static [Vec<Access>] {
        static ALL: std::sync::OnceLock<Vec<Vec<Access>>> = std::sync::OnceLock::new();
        ALL.get_or_init(|| {
            (0u32..1 << UNIVERSE.len())
                .map(|mask| {
                    UNIVERSE
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask & (1 << i) != 0)
                        .map(|(_, a)| *a)
                        .collect()
                })
                .collect()
        })
    }

    fn host() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("site.example.org".to_string()),
            Just("SITE.EXAMPLE.ORG".to_string()),
            "[a-z]{1,8}\\.example\\.org",
        ]
    }

    proptest! {
        /// An arbitrary request never has a credential, whatever it names and wherever it goes.
        #[test]
        fn an_arbitrary_request_never_gets_a_credential(
            host in host(),
            encrypted in any::<bool>(),
            configured in proptest::option::of(host()),
            chosen in proptest::option::of("[a-z]{1,8}"),
        ) {
            const ARBITRARY: OperationDecl = declared(Location::Arbitrary);
            let verdict = judge(&ARBITRARY, &[ARBITRARY], &target(&host, encrypted), configured.as_deref(), chosen.as_deref());
            prop_assert_eq!(verdict, allowed(None));
        }

        /// Whatever is asked, an undeclared operation is denied.
        #[test]
        fn nothing_undeclared_is_allowed(
            location in location(),
            host in host(),
            encrypted in any::<bool>(),
            configured in proptest::option::of(host()),
            chosen in proptest::option::of("[a-z]{1,8}"),
        ) {
            let operation = declared(location);
            let verdict = judge(&operation, &[], &target(&host, encrypted), configured.as_deref(), chosen.as_deref());
            prop_assert_eq!(verdict, Verdict::Deny(Denial::Undeclared));
        }

        /// A credential is allowed only over an encrypted connection, only for an operation that declares one, and only
        /// the one it declares or names; and a configured operation goes only to the configured host.
        #[test]
        fn what_is_allowed_follows_the_declaration(
            location in location(),
            host in host(),
            encrypted in any::<bool>(),
            configured in proptest::option::of(host()),
            chosen in proptest::option::of("[a-z]{1,8}"),
        ) {
            let operation = declared(location);
            let verdict = judge(&operation, &[operation], &target(&host, encrypted), configured.as_deref(), chosen.as_deref());
            if let Verdict::Allow { credential } = verdict {
                let declares = match location {
                    Location::Configured { credential, .. } => credential,
                    Location::Bound { credential } => Some(credential),
                    Location::Arbitrary | Location::Cluster { .. } => None,
                };
                if let Location::Cluster { .. } = location {
                    prop_assert!(encrypted);
                }
                match (declares, credential) {
                    (None, given) => prop_assert_eq!(given, None),
                    (Some(_), None) => prop_assert!(false, "an operation that needs a credential was allowed without one"),
                    (Some(Credential::Named(name)), Some(given)) => {
                        prop_assert!(encrypted);
                        prop_assert_eq!(given, name);
                    }
                    (Some(Credential::Chosen | Credential::ForHost), Some(given)) => {
                        prop_assert!(encrypted);
                        prop_assert_eq!(Some(given.as_str()), chosen.as_deref());
                    }
                }
                if let Location::Configured { .. } = location {
                    let configured = configured.expect("a configured request needs its host set");
                    prop_assert!(host.eq_ignore_ascii_case(&configured));
                }
            }
        }

        /// A bound request is always one for the CryptoActor to check, never allowed without a credential to check:
        /// over an encrypted connection, an operation that names its own is always asked for it.
        #[test]
        fn a_bound_operation_that_names_its_credential_is_left_to_the_binding(host in host()) {
            const NAMED: OperationDecl = declared(Location::Bound { credential: Credential::Named("site") });
            prop_assert_eq!(judge(&NAMED, &[NAMED], &target(&host, true), None, None), allowed(Some("site")));
        }

        /// A cluster request is allowed when, and only when, it goes encrypted and does what its operation declares.
        #[test]
        fn a_cluster_request_is_allowed_exactly_when_encrypted_and_declared(
            declaration in 0usize..64,
            wanted in proptest::option::of(proptest::sample::select(UNIVERSE.to_vec())),
            encrypted in any::<bool>(),
            chosen in proptest::option::of("[a-z]{1,8}"),
        ) {
            let access: &'static [Access] = &declarations()[declaration];
            let operation = declared(Location::Cluster { access, namespace: None });
            let verdict = judge(&operation, &[operation], &to_the_cluster(encrypted, wanted), None, chosen.as_deref());
            let expected = if !encrypted {
                Verdict::Deny(Denial::NotEncrypted)
            } else if wanted.is_some_and(|w| access.contains(&w)) {
                allowed(None)
            } else {
                Verdict::Deny(Denial::AccessUndeclared)
            };
            prop_assert_eq!(verdict, expected);
        }

        /// A request of a cluster operation that names a namespace is allowed only in the namespace the deployment names
        /// for its key: never in another, never across the cluster, and never while the deployment names none. One that
        /// names no namespace is held to none.
        #[test]
        fn a_cluster_request_outside_its_operation_s_namespace_is_always_refused(
            held in proptest::option::of(proptest::sample::select(vec!["builds", "core"])),
            configured in proptest::option::of(proptest::sample::select(vec!["polar-builds", "polar", "kube-system"])),
            acts_in in proptest::option::of(proptest::sample::select(vec!["polar-builds", "polar", "kube-system", "builds"])),
            encrypted in any::<bool>(),
        ) {
            let operation = declared(Location::Cluster { access: &[CREATE_JOBS], namespace: held });
            let target = Target {
                namespace: acts_in.map(str::to_string),
                ..to_the_cluster(encrypted, Some(CREATE_JOBS))
            };
            let verdict = judge(&operation, &[operation], &target, configured, None);
            let expected = if !encrypted {
                Verdict::Deny(Denial::NotEncrypted)
            } else if held.is_none() {
                allowed(None)
            } else if configured.is_none() {
                Verdict::Deny(Denial::NamespaceUnknown)
            } else if acts_in != configured {
                Verdict::Deny(Denial::OutsideTheNamespace)
            } else {
                allowed(None)
            };
            prop_assert_eq!(&verdict, &expected);
            if held.is_some() && verdict == allowed(None) {
                prop_assert_eq!(acts_in, configured);
            }
        }
    }
}
