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

//! A repository whose every commit must be signed (docs/architecture/cluster-bootstrap.md, "Handing off to Polar's git server"). A deployment repository is
//! what Flux deploys, so write access to it must not be enough to change what runs: a push is taken only if every commit it brings is signed by the
//! pipeline's certificate, chaining to the deployment CA. Nothing here is in the way of any other repository.
//!
//! A push is judged in gix-serve's quarantine (src/git.rs): its pack is indexed beside the repository's objects, so what is judged is what would be
//! stored, and a refused push leaves nothing behind.

use crate::config::{RepoSpec, SignedBy};
use crate::pktline::RefUpdate;
use polar_signing::Trust;
use polar_signing::commit::verify_commit;
use std::collections::{BTreeSet, HashMap};

/// The rule of one repository.
pub struct CommitPolicy {
    trust: Trust,
    signer: String,
}

impl CommitPolicy {
    pub fn new(ca_pem: &str, signer: &str) -> Result<Self, String> {
        Ok(Self {
            trust: Trust::from_pem(&[ca_pem.to_string()]).map_err(|e| e.to_string())?,
            signer: signer.to_string(),
        })
    }
}

/// The rules of the repositories that have one.
#[derive(Default)]
pub struct SignedRepos {
    policies: HashMap<String, CommitPolicy>,
}

impl SignedRepos {
    pub fn new(policies: HashMap<String, CommitPolicy>) -> Self {
        Self { policies }
    }

    /// The rules the configuration declares. A CA that cannot be read stops the server: a repository left open because a file is missing is
    /// the failure this exists to prevent.
    pub fn from_specs(specs: &[RepoSpec]) -> Result<Self, String> {
        let mut policies = HashMap::new();
        for spec in specs {
            if let Some(SignedBy { ca, signer }) = &spec.signed_by {
                let pem = std::fs::read_to_string(ca).map_err(|e| {
                    format!(
                        "{}: the CA its commits must chain to, {}: {e}",
                        spec.name,
                        ca.display()
                    )
                })?;
                let policy =
                    CommitPolicy::new(&pem, signer).map_err(|e| format!("{}: {e}", spec.name))?;
                policies.insert(spec.name.clone(), policy);
            }
        }
        Ok(Self { policies })
    }

    pub fn policy_of(&self, repo: &str) -> Option<&CommitPolicy> {
        self.policies.get(repo)
    }
}

/// The time now, in seconds since the epoch.
pub fn wall_clock() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether a push may be taken: every commit it brings, and the head of every ref it moves, is signed as the repository requires. `repo` is the
/// repository with the push's objects in quarantine beside it. (Every repository refuses a deletion by its own configuration, `store.rs`, which
/// gix-serve holds a push to before this.) A commit already on the server gets no pass as a head, so a ref cannot be pointed at something taken before
/// the rule was.
pub fn check_push(
    repo: &gix::Repository,
    policy: &CommitPolicy,
    updates: &[RefUpdate],
    now: i64,
) -> Result<(), String> {
    for pushed in pushed_commits(repo, updates)? {
        let at = checked_at(pushed.head, committer_time(&pushed.raw), now);
        verify_commit(&pushed.raw, &policy.trust, &policy.signer, at)
            .map_err(|why| format!("commit {} is refused: {why}", pushed.commit))?;
    }
    Ok(())
}

/// A commit a push brings, or points a ref at.
pub(crate) struct Pushed {
    pub(crate) commit: String,
    /// Whether a ref is to point at it.
    pub(crate) head: bool,
    /// The commit object, as `git cat-file commit` gives it.
    pub(crate) raw: Vec<u8>,
}

/// Every commit a push brings that no ref of the repository reaches, for each of `updates`, and the head of every ref they move, held or not, as
/// `git rev-list <new> --not --all` lists them. `repo` is the repository with the push's objects in quarantine beside it. A deletion brings nothing.
pub(crate) fn pushed_commits(
    repo: &gix::Repository,
    updates: &[RefUpdate],
) -> Result<Vec<Pushed>, String> {
    let held = held_commits(repo)?;
    let mut pushed = Vec::new();
    for update in updates {
        let new = gix::ObjectId::from_hex(update.new.as_bytes())
            .map_err(|e| format!("{} is not an object id: {e}", update.new))?;
        if new.is_null() {
            continue;
        }
        if repo.find_header(new).map(|h| h.kind()).ok() != Some(gix::object::Kind::Commit) {
            return Err(format!("{} is not a commit", update.new));
        }
        let mut judged: BTreeSet<gix::ObjectId> = BTreeSet::from([new]);
        for info in repo
            .rev_walk([new])
            .with_hidden(held.iter().copied())
            .all()
            .map_err(|e| format!("the history of {new} cannot be walked: {e}"))?
        {
            let info = info.map_err(|e| format!("the history of {new} cannot be walked: {e}"))?;
            judged.insert(info.id);
        }
        for commit in judged {
            let raw = repo
                .find_object(commit)
                .map_err(|e| format!("commit {commit} cannot be read: {e}"))?
                .detach()
                .data;
            pushed.push(Pushed {
                commit: commit.to_string(),
                head: commit == new,
                raw,
            });
        }
    }
    Ok(pushed)
}

/// The commits the repository's refs point at, through annotated tags: what a push's history is walked back to.
fn held_commits(repo: &gix::Repository) -> Result<Vec<gix::ObjectId>, String> {
    let mut held = Vec::new();
    for reference in repo
        .references()
        .and_then(|platform| platform.all().map(|all| all.collect::<Vec<_>>()))
        .map_err(|e| format!("the refs cannot be listed: {e}"))?
    {
        let mut reference = reference.map_err(|e| format!("a ref cannot be read: {e}"))?;
        if let Ok(id) = reference.peel_to_id()
            && repo.find_header(id).map(|h| h.kind()).ok() == Some(gix::object::Kind::Commit)
        {
            held.push(id.detach());
        }
    }
    Ok(held)
}

/// When a commit's certificate must have been valid. A head goes live now, so its certificate must be valid now. What is under it was signed when it
/// was, and a certificate that has since expired does not undo that, or a repository could not be copied a year on. A commit says when it was made inside what
/// is signed, so only the certificate's holder could backdate one. A commit that does not say is judged as of now.
fn checked_at(head: bool, committed: Option<i64>, now: i64) -> i64 {
    match (head, committed) {
        (false, Some(when)) => when,
        _ => now,
    }
}

/// The time on a commit's `committer` header.
pub(crate) fn committer_time(raw: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(raw).ok()?;
    let line = text
        .lines()
        .take_while(|l| !l.is_empty())
        .find(|l| l.starts_with("committer "))?;
    line.rsplit(' ').nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_is_judged_now_and_what_is_under_it_when_it_was_made() {
        assert_eq!(checked_at(true, Some(100), 500), 500);
        assert_eq!(checked_at(false, Some(100), 500), 100);
        assert_eq!(checked_at(false, None, 500), 500);
        assert_eq!(checked_at(true, None, 500), 500);
    }

    #[test]
    fn the_time_is_the_committers_and_only_from_the_headers() {
        let raw = b"tree a\nauthor x <x@y> 111 +0000\ncommitter x <x@y> 222 -0500\n\ncommitter z <z@y> 333 +0000\n";
        assert_eq!(committer_time(raw), Some(222));
        assert_eq!(
            committer_time(b"tree a\n\ncommitter z <z@y> 333 +0000\n"),
            None
        );
        assert_eq!(committer_time(b"committer who knows\n"), None);
    }

    #[test]
    fn a_ca_that_cannot_be_read_stops_the_server_rather_than_leaving_the_repository_open() {
        let specs = [RepoSpec {
            name: "deploy-t".into(),
            readers: vec![],
            writers: vec![],
            seed: None,
            signed_by: Some(SignedBy {
                ca: "/nonexistent/ca.pem".into(),
                signer: "pipeline".into(),
            }),
        }];
        assert!(SignedRepos::from_specs(&specs).is_err());
    }
}
