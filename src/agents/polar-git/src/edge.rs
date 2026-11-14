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

//! polar-git's edge (docs/architecture/polar-git.md): what each git request is, as policy is asked of it, and the
//! asking. Every request is judged by the identity the client's certificate gives, as the broker judges a message by the
//! identity it stamped, and the policy actor reads that person's groups and capabilities from the same certificate. Only
//! an allow allows (`polar_policy::git`).
//!
//! A ref update is one of: a branch made or moved forward (push), a branch moved to a commit it does not lead to (force
//! push), a branch deleted (delete), or any change to a tag (tag). Anything else under `refs/` is refused, as a git
//! server keeps its own refs.

use polar_git_server::pktline::RefUpdate;
use polar_policy::git::{GitAction, RESOURCE_TYPE, verdict};
use polar_policy::{Facts, PolicyMessage};
use ractor::ActorRef;
use tracing::warn;

/// Who is asking: the identity their certificate gives, the name people read them by, and that certificate, PEM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Who {
    pub identity: String,
    /// A person's username, the `uid` in their certificate's Subject; a workload's identity where there is none.
    pub name: String,
    pub certificate_pem: String,
}

impl Who {
    /// Who a connection's identity and leaf certificate (DER) say is asking.
    pub fn of(identity: &str, certificate_der: &[u8]) -> Self {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        Self {
            identity: identity.to_string(),
            name: username(certificate_der).unwrap_or_else(|| identity.to_string()),
            certificate_pem: pem,
        }
    }
}

/// The `uid` in a certificate's Subject: a person's username, as cert-issuer writes it from their account.
fn username(certificate_der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(certificate_der).ok()?;
    let uid = x509_parser::der_parser::oid::Oid::from(&[0, 9, 2342, 19200300, 100, 1, 1]).ok()?;
    cert.subject()
        .iter_by_oid(&uid)
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_string)
}

/// What `update` does, as policy is asked of it, judged against `repo`, which holds the push's objects (in quarantine).
pub fn classify(repo: &gix::Repository, update: &RefUpdate) -> Result<GitAction, String> {
    if update.refname.starts_with("refs/tags/") {
        return Ok(GitAction::Tag);
    }
    if !update.refname.starts_with("refs/heads/") {
        return Err(format!("{} is not a branch or a tag", update.refname));
    }
    let id = |hex: &str| {
        gix::ObjectId::from_hex(hex.as_bytes())
            .map_err(|e| format!("{hex} is not an object id: {e}"))
    };
    let (old, new) = (id(&update.old)?, id(&update.new)?);
    if new.is_null() {
        return Ok(GitAction::Delete);
    }
    if old.is_null() || leads_to(repo, new, old)? {
        return Ok(GitAction::Push);
    }
    Ok(GitAction::ForcePush)
}

/// Whether `old` is in the history of `new`, so moving a branch from one to the other moves it forward.
fn leads_to(
    repo: &gix::Repository,
    new: gix::ObjectId,
    old: gix::ObjectId,
) -> Result<bool, String> {
    let walk = repo
        .rev_walk([new])
        .all()
        .map_err(|e| format!("the history of {new} cannot be read: {e}"))?;
    for commit in walk {
        let commit = commit.map_err(|e| format!("the history of {new} cannot be read: {e}"))?;
        if commit.id == old {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What says whether someone may do something to a repository.
#[ractor::async_trait]
pub trait Asker: Send + Sync {
    /// Whether `who` may do `action` to `repo`, whose owner is `owner` (none when it has none, or is not there yet).
    async fn may(&self, who: &Who, action: GitAction, repo: &str, owner: Option<&str>) -> bool;
}

/// The agent's policy actor, asked; with none, nothing is allowed.
pub struct PolicyAsker(pub Option<ActorRef<PolicyMessage>>);

#[ractor::async_trait]
impl Asker for PolicyAsker {
    async fn may(&self, who: &Who, action: GitAction, repo: &str, owner: Option<&str>) -> bool {
        let Some(policy) = &self.0 else {
            return false;
        };
        let (Some(action_uid), Some(resource)) = (
            polar_agent_builder::policy_authority::entity("Action", action.name()),
            polar_agent_builder::policy_authority::entity(RESOURCE_TYPE, repo),
        ) else {
            return false;
        };
        let answer = ractor::call!(policy, |reply| PolicyMessage::CheckAuthorization {
            requester_identity: who.identity.clone(),
            requester_certificate_pem: Some(who.certificate_pem.clone()),
            action: action_uid,
            resource,
            facts: Facts {
                owner: owner.map(str::to_string),
                ..Facts::default()
            },
            reply,
        });
        match answer {
            Ok(answer) => verdict(Some(answer)),
            Err(e) => {
                warn!(error = %e, "the policy actor did not answer, so the request is refused");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(repo: &gix::Repository, parents: &[gix::ObjectId], message: &str) -> gix::ObjectId {
        let tree = gix::ObjectId::empty_tree(repo.object_hash());
        repo.commit_as(
            gix::actor::SignatureRef::default(),
            gix::actor::SignatureRef::default(),
            "refs/heads/scratch",
            message,
            tree,
            parents.iter().copied(),
        )
        .map(|id| id.detach())
        .unwrap_or_else(|_| {
            // A commit whose parent is not the ref's tip: written as an object, the ref left alone.
            let object = gix::objs::Commit {
                tree,
                parents: parents.iter().copied().collect(),
                author: Default::default(),
                committer: Default::default(),
                encoding: None,
                message: message.into(),
                extra_headers: vec![],
            };
            repo.write_object(&object).unwrap().detach()
        })
    }

    fn update(refname: &str, old: gix::ObjectId, new: gix::ObjectId) -> RefUpdate {
        RefUpdate {
            old: old.to_string(),
            new: new.to_string(),
            refname: refname.into(),
        }
    }

    /// Each kind of ref update is the action policy is asked for it: a branch made or moved forward is a push, moved
    /// elsewhere a force push, removed a delete; anything to a tag is a tag; anything else is no branch or tag.
    #[test]
    fn each_ref_update_is_the_action_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init_bare(dir.path()).unwrap();
        let null = gix::ObjectId::null(repo.object_hash());
        let a = commit(&repo, &[], "a");
        let b = commit(&repo, &[a], "b");
        let c = commit(&repo, &[a], "c");
        assert_eq!(
            classify(&repo, &update("refs/heads/main", null, a)),
            Ok(GitAction::Push)
        );
        assert_eq!(
            classify(&repo, &update("refs/heads/main", a, b)),
            Ok(GitAction::Push)
        );
        assert_eq!(
            classify(&repo, &update("refs/heads/main", b, c)),
            Ok(GitAction::ForcePush)
        );
        assert_eq!(
            classify(&repo, &update("refs/heads/main", b, a)),
            Ok(GitAction::ForcePush)
        );
        assert_eq!(
            classify(&repo, &update("refs/heads/main", b, null)),
            Ok(GitAction::Delete)
        );
        for (old, new) in [(null, a), (a, b), (b, null)] {
            assert_eq!(
                classify(&repo, &update("refs/tags/v1", old, new)),
                Ok(GitAction::Tag)
            );
        }
        assert!(classify(&repo, &update("refs/notes/commits", null, a)).is_err());
        assert!(classify(&repo, &update("HEAD", null, a)).is_err());
        let bad = RefUpdate {
            old: "not hex".into(),
            new: a.to_string(),
            refname: "refs/heads/main".into(),
        };
        assert!(classify(&repo, &bad).is_err());
    }

    #[test]
    fn a_certificate_is_given_to_policy_as_the_pem_it_came_as() {
        let who = Who::of("alice", &[1u8; 100]);
        assert_eq!(who.identity, "alice");
        assert_eq!(who.name, "alice", "no certificate to read: its identity");
        assert!(
            who.certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----\n")
        );
        assert!(who.certificate_pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(
            who.certificate_pem
                .lines()
                .all(|l| l.len() <= 64 || l.starts_with("-----"))
        );
    }

    /// A person is named by the username in their certificate's Subject, and their identity is still their identity.
    #[test]
    fn a_person_is_named_by_their_username() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(
            rcgen::DnType::CustomDnType(vec![0, 9, 2342, 19200300, 100, 1, 1]),
            "djshepard",
        );
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let who = Who::of("15ab472c-cdd3-4b24-948f-30f9ca5f8cc9", &der);
        assert_eq!(who.name, "djshepard");
        assert_eq!(who.identity, "15ab472c-cdd3-4b24-948f-30f9ca5f8cc9");
    }

    /// With no policy actor, nothing is allowed.
    #[tokio::test]
    async fn with_no_policy_nothing_is_allowed() {
        let who = Who::of("alice", &[1]);
        for action in GitAction::ALL {
            assert!(
                !PolicyAsker(None)
                    .may(&who, action, "tools", Some("alice"))
                    .await
            );
        }
    }
}
