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

//! What a person may do with source code on polar-git (docs/architecture/polar-git.md): policy alone decides. Each git
//! operation is an action on `Repository::"<name>"`, with the repository's owner, the identity that made it, as its
//! attribute `owner`, so a rule can say "its owner may do anything to it". Cedar overrides both ways as everywhere, and
//! where it is silent the certificate would decide, but a certificate names no git rights, so silence refuses: a
//! person does with a repository exactly what the signed policy lets them, and nothing here fails open.

use crate::{Decision, PolicyError};

/// The resource type of a repository.
pub const RESOURCE_TYPE: &str = "Repository";

/// One thing done to a repository, as policy is asked of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GitAction {
    /// Fetching or cloning it.
    Read,
    /// Making a branch, or moving one forward.
    Push,
    /// Moving a branch to a commit it does not lead to: a rewrite.
    ForcePush,
    /// Deleting a branch.
    Delete,
    /// Making, moving or deleting a tag.
    Tag,
    /// Making a repository.
    Create,
}

impl GitAction {
    pub const ALL: [GitAction; 6] = [
        GitAction::Read,
        GitAction::Push,
        GitAction::ForcePush,
        GitAction::Delete,
        GitAction::Tag,
        GitAction::Create,
    ];

    /// The action's name, as a rule writes it in `Action::"…"`.
    pub fn name(self) -> &'static str {
        match self {
            GitAction::Read => "git-read",
            GitAction::Push => "git-push",
            GitAction::ForcePush => "git-force-push",
            GitAction::Delete => "git-delete",
            GitAction::Tag => "git-tag",
            GitAction::Create => "git-create",
        }
    }
}

/// Whether what policy said (none loaded: `None`) allows it: only an `Allow`. Silence, a forbid, no policy, and a rule
/// that cannot be evaluated all refuse.
pub fn verdict(policy: Option<Result<Decision, PolicyError>>) -> bool {
    matches!(policy, Some(Ok(Decision::Allow)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Evaluator, Facts, Requester};
    use cert_issuer_common::hierarchy::Hierarchy;

    fn evaluator(source: &str) -> Evaluator {
        Evaluator::new(source, &Hierarchy::default()).unwrap()
    }

    fn ask(
        policy: &Evaluator,
        who: &str,
        groups: &[String],
        action: GitAction,
        owner: Option<&str>,
    ) -> bool {
        let requester = Requester {
            identity: who,
            groups,
            capabilities: &[],
            permissions: &[],
        };
        let facts = Facts {
            owner: owner.map(str::to_string),
            ..Facts::default()
        };
        verdict(Some(policy.decide(
            &requester,
            &format!("Action::\"{}\"", action.name()),
            &format!("{RESOURCE_TYPE}::\"tools\""),
            &facts,
            0,
        )))
    }

    /// The rules the first policy of a cluster gives (infra/seeds/signed/policy.cedar): a repo developer makes, reads,
    /// pushes and tags; the owner of a repository may also force and delete in it.
    const FIRST: &str = r#"
        permit (principal in Group::"repo-developers", action in [Action::"git-create", Action::"git-read", Action::"git-push", Action::"git-tag"], resource);
        permit (principal, action in [Action::"git-read", Action::"git-push", Action::"git-tag", Action::"git-force-push", Action::"git-delete"], resource)
        when { resource has owner && resource.owner == principal };
    "#;

    #[test]
    fn a_repo_developer_works_in_any_repository_and_rewrites_only_their_own() {
        let policy = evaluator(FIRST);
        let developers = vec!["repo-developers".to_string()];
        for action in [
            GitAction::Create,
            GitAction::Read,
            GitAction::Push,
            GitAction::Tag,
        ] {
            assert!(
                ask(&policy, "alice", &developers, action, Some("bob")),
                "{action:?}"
            );
        }
        for action in [GitAction::ForcePush, GitAction::Delete] {
            assert!(
                !ask(&policy, "alice", &developers, action, Some("bob")),
                "{action:?}"
            );
            assert!(
                ask(&policy, "alice", &developers, action, Some("alice")),
                "{action:?}"
            );
        }
    }

    #[test]
    fn someone_policy_says_nothing_of_may_do_nothing() {
        let policy = evaluator(FIRST);
        for action in GitAction::ALL {
            assert!(
                !ask(&policy, "mallory", &[], action, Some("bob")),
                "{action:?}"
            );
        }
        // With no owner known, the owner's rule cannot apply.
        assert!(!ask(&policy, "alice", &[], GitAction::ForcePush, None));
    }

    #[test]
    fn a_forbid_withdraws_what_a_group_gives() {
        let policy = evaluator(&format!(
            r#"{FIRST} forbid (principal == Identity::"alice", action == Action::"git-push", resource);"#
        ));
        let developers = vec!["repo-developers".to_string()];
        assert!(!ask(
            &policy,
            "alice",
            &developers,
            GitAction::Push,
            Some("alice")
        ));
        assert!(ask(
            &policy,
            "alice",
            &developers,
            GitAction::Read,
            Some("alice")
        ));
    }

    #[test]
    fn each_action_has_its_own_name_and_the_schema_knows_it() {
        let names: std::collections::BTreeSet<_> =
            GitAction::ALL.iter().map(|a| a.name()).collect();
        assert_eq!(names.len(), GitAction::ALL.len());
        for action in GitAction::ALL {
            let rule = format!(
                r#"permit (principal, action == Action::"{}", resource);"#,
                action.name()
            );
            assert!(crate::validate_source(&rule).is_ok(), "{rule}");
        }
    }

    /// Only an allow allows: a forbid, silence, no policy, and a policy that cannot answer all refuse.
    #[test]
    fn only_an_allow_allows() {
        assert!(verdict(Some(Ok(Decision::Allow))));
        assert!(!verdict(Some(Ok(Decision::Deny))));
        assert!(!verdict(Some(Ok(Decision::NotDetermined))));
        assert!(!verdict(Some(Err(PolicyError::NoPolicyLoaded))));
        assert!(!verdict(None));
    }
}
