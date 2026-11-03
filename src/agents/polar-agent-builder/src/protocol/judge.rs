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

/// The protocols a handler exists for. An operation says which it is for, and the builder starts those at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolKind {
    /// Only in this crate's tests, for the framework alone.
    #[cfg(test)]
    Test,
}

impl ProtocolKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            #[cfg(test)]
            ProtocolKind::Test => "test",
        }
    }
}

/// Which credential a request uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// The one with this name: an entry of the agent's `credentials` section.
    Named(&'static str),
    /// One the request names ([`super::Operation::credential`]), as a repository's configuration names its own.
    Chosen,
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

/// Where a request would go, as its protocol reads it from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    /// Whether the connection is encrypted: a credential goes over no other.
    pub encrypted: bool,
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

/// Whether `operation` may go to `target`. `declared` is what the agent declared; `configured_host` is the host of the
/// operation's variable as it is in force, if it has one and it is set; `chosen` is the credential the request names.
pub fn judge(
    operation: &OperationDecl,
    declared: &[OperationDecl],
    target: &Target,
    configured_host: Option<&str>,
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
            let Some(configured) = configured_host else {
                return Verdict::Deny(Denial::NotConfigured);
            };
            if !target.host.eq_ignore_ascii_case(configured) {
                return Verdict::Deny(Denial::OffTheConfiguredHost);
            }
            credential
        }
        Location::Bound { credential } => Some(credential),
        Location::Arbitrary => None,
    };
    let credential = match credential {
        None => None,
        Some(Credential::Named(name)) => Some(name.to_string()),
        Some(Credential::Chosen) => match chosen {
            Some(name) => Some(name.to_string()),
            None => return Verdict::Deny(Denial::NoCredentialNamed),
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
            protocol: ProtocolKind::Test,
            location,
        }
    }

    fn target(host: &str, encrypted: bool) -> Target {
        Target {
            host: host.to_string(),
            encrypted,
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

    fn credential() -> impl Strategy<Value = Credential> {
        prop_oneof![Just(Credential::Named("site")), Just(Credential::Chosen)]
    }

    fn location() -> impl Strategy<Value = Location> {
        prop_oneof![
            proptest::option::of(credential()).prop_map(|credential| Location::Configured {
                variable: "SITE_URL",
                credential,
            }),
            credential().prop_map(|credential| Location::Bound { credential }),
            Just(Location::Arbitrary),
        ]
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
                    Location::Arbitrary => None,
                };
                match (declares, credential) {
                    (None, given) => prop_assert_eq!(given, None),
                    (Some(_), None) => prop_assert!(false, "an operation that needs a credential was allowed without one"),
                    (Some(Credential::Named(name)), Some(given)) => {
                        prop_assert!(encrypted);
                        prop_assert_eq!(given, name);
                    }
                    (Some(Credential::Chosen), Some(given)) => {
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
    }
}
