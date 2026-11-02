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
//! Git is given the push only after it passes. The pack is read into a quarantine beside the repository, so what is judged is what would be stored, and a
//! refused push leaves nothing behind.

use crate::config::{RepoSpec, SignedBy};
use crate::pktline::RefUpdate;
use polar_signing::Trust;
use polar_signing::commit::verify_commit;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

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

/// How long git is given for one step of judging a push.
const GIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Tells a quarantine's directories apart within one process.
static QUARANTINES: AtomicU64 = AtomicU64::new(0);

/// Whether a push may be given to git: every commit it brings, and the head of every ref it moves, is signed as the repository requires. (Every
/// repository refuses a deletion by its own configuration, `store.rs`.) A commit already on the server gets no pass as a head, so a ref cannot be pointed at something taken before the rule was.
pub async fn check_push(
    repo: &Path,
    policy: &CommitPolicy,
    updates: &[RefUpdate],
    pack: &[u8],
    now: i64,
) -> Result<(), String> {
    let quarantine = Quarantine::new(repo)?;
    if !pack.is_empty() {
        quarantine
            .git(&["index-pack", "--stdin", "--fix-thin"], pack)
            .await?;
    }
    for update in updates {
        let listed = quarantine
            .git(&["rev-list", &update.new, "--not", "--all"], &[])
            .await?;
        let listed = String::from_utf8_lossy(&listed);
        let mut judged: BTreeSet<&str> = listed.lines().collect();
        judged.insert(update.new.as_str());
        for commit in judged {
            let raw = quarantine.git(&["cat-file", "commit", commit], &[]).await?;
            let at = checked_at(commit == update.new, committer_time(&raw), now);
            verify_commit(&raw, &policy.trust, &policy.signer, at)
                .map_err(|why| format!("commit {commit} is refused: {why}"))?;
        }
    }
    Ok(())
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
fn committer_time(raw: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(raw).ok()?;
    let line = text
        .lines()
        .take_while(|l| !l.is_empty())
        .find(|l| l.starts_with("committer "))?;
    line.rsplit(' ').nth(1)?.parse().ok()
}

/// A place beside the repository where a push's objects can be read before they are taken, removed when it goes out of scope.
struct Quarantine<'a> {
    repo: &'a Path,
    dir: PathBuf,
}

impl<'a> Quarantine<'a> {
    fn new(repo: &'a Path) -> Result<Self, String> {
        let dir = repo.join(format!(
            "polar-quarantine-{}-{}",
            std::process::id(),
            QUARANTINES.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("pack"))
            .map_err(|e| format!("cannot make a quarantine: {e}"))?;
        Ok(Self { repo, dir })
    }

    /// Runs git in the repository, where what is written goes to the quarantine and what is read comes from there or from the repository.
    async fn git(&self, args: &[&str], stdin: &[u8]) -> Result<Vec<u8>, String> {
        let mut command = Command::new("git");
        command
            .args(args)
            .env("GIT_DIR", self.repo)
            .env("GIT_OBJECT_DIRECTORY", &self.dir)
            .env(
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                self.repo.join("objects"),
            )
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot run git {}: {e}", args[0]))?;
        let mut input = child.stdin.take().expect("stdin is piped");
        let body = stdin.to_vec();
        let feed = tokio::spawn(async move {
            // A process that exits early closes the pipe; its status says what happened.
            let _ = input.write_all(&body).await;
            let _ = input.shutdown().await;
        });
        let out = tokio::time::timeout(GIT_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| format!("git {} did not finish in time", args[0]))?
            .map_err(|e| format!("git {}: {e}", args[0]))?;
        let _ = feed.await;
        if !out.status.success() {
            return Err(format!(
                "git {}: {}",
                args[0],
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    }
}

impl Drop for Quarantine<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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
