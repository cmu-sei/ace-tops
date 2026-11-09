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

//! `--push`: putting a signed document into the schedules repository. The tool clones the repository into a
//! working folder (or brings the folder it has up to date), writes the file at its place, commits only that file
//! and pushes. It runs the author's own `git`, so their git configuration, their certificate for the Polar git
//! server and any commit signing they have set up all apply.
//!
//! The file's place is `permanent/<agent>/<section>.dhall` (`configuration.dhall` for an agent's settings): one
//! file per thing, so a new version replaces the old one in place and git keeps the history. The polar scheduler's
//! observer already reads anything under `permanent/`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The commit message for a document: a conventional one, since an author's git may check for that
/// (`feat(<agent>): <section> version <n>`, or `settings` for an agent's settings).
pub fn message(agent: &str, section: Option<&str>, version: u64, signer: &str) -> String {
    format!(
        "feat({agent}): {} version {version}\n\nSigned by {signer} with polar-sign.",
        section.unwrap_or("settings")
    )
}

/// Where a document goes in the repository.
pub fn place(agent: &str, section: Option<&str>) -> String {
    format!(
        "permanent/{agent}/{}.dhall",
        section.unwrap_or("configuration")
    )
}

pub struct Plan<'a> {
    /// Where the repository is (anything `git clone` takes).
    pub remote: &'a str,
    /// The folder the tool keeps its clone in.
    pub workdir: &'a Path,
    /// The file's place in the repository.
    pub relative: &'a str,
    pub content: &'a str,
    pub message: &'a str,
    pub author_name: &'a str,
    pub author_email: &'a str,
    /// `git -c key=value` for every git command: the certificate and CA for the Polar git server, for one.
    pub git_config: &'a [(String, String)],
}

#[derive(Debug, PartialEq, Eq)]
pub enum Pushed {
    /// A commit was made and pushed.
    Pushed,
    /// The repository already held exactly this file; nothing was done.
    Unchanged,
}

fn git(
    config: &[(String, String)],
    in_dir: Option<&Path>,
    args: &[&str],
) -> Result<String, String> {
    let mut command = Command::new("git");
    for (key, value) in config {
        command.arg("-c").arg(format!("{key}={value}"));
    }
    if let Some(dir) = in_dir {
        command.arg("-C").arg(dir);
    }
    command.args(args);
    // Never wait for a password nobody can type.
    command.env("GIT_TERMINAL_PROMPT", "0");
    // GIT_SSL_CAINFO and SSL_CERT_FILE in the environment would override the CA given here (`http.sslCAInfo`);
    // `just polar-git-clone` clears both for the same reason.
    if config.iter().any(|(k, _)| k == "http.sslCAInfo") {
        command.env_remove("GIT_SSL_CAINFO");
        command.env_remove("SSL_CERT_FILE");
    }
    let output = command
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let last: Vec<&str> = stderr.lines().rev().take(3).collect();
        Err(format!(
            "`git {}` failed: {}",
            args.first().copied().unwrap_or(""),
            last.into_iter().rev().collect::<Vec<_>>().join(" | ")
        ))
    }
}

/// Whether `dir` is a clone of `remote`.
fn clone_of(config: &[(String, String)], remote: &str, dir: &Path) -> Result<bool, String> {
    Ok(git(config, Some(dir), &["remote", "get-url", "origin"])? == remote)
}

/// The tool's clone of `remote` in `workdir`, as the repository's branch holds it now: cloned if there is none, and
/// otherwise reset to what the branch holds, whatever the clone's own history. The clone is the tool's cache, nothing of
/// the author's: a repository made again at the same address (a cluster brought up anew) leaves a clone whose history
/// cannot be fast-forwarded, which `pull --ff-only` refused (Vaughn's finding, 2026-11-04). A folder that is another
/// repository's clone is refused, not touched.
pub fn up_to_date(remote: &str, workdir: &Path, config: &[(String, String)]) -> Result<(), String> {
    if workdir.join(".git").exists() {
        if !clone_of(config, remote, workdir)? {
            return Err(format!(
                "{} is a working folder for another repository; give --workdir another place",
                workdir.display()
            ));
        }
        let branch = git(config, Some(workdir), &["symbolic-ref", "--short", "HEAD"])?;
        let held = git(
            config,
            Some(workdir),
            &["ls-remote", "--heads", "origin", &branch],
        )?;
        if !held.is_empty() {
            git(config, Some(workdir), &["fetch", "-q", "origin", &branch])?;
            git(
                config,
                Some(workdir),
                &["reset", "-q", "--hard", "FETCH_HEAD"],
            )?;
            return Ok(());
        }
        // The repository holds nothing on that branch: one made again, still empty. What the clone holds is another
        // history's, so it is cloned afresh rather than pushed into it.
        if git(
            config,
            Some(workdir),
            &["rev-parse", "--verify", "-q", "HEAD"],
        )
        .is_err()
        {
            return Ok(());
        }
        std::fs::remove_dir_all(workdir)
            .map_err(|e| format!("cannot clear {}: {e}", workdir.display()))?;
    }
    if let Some(parent) = workdir.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot make {}: {e}", parent.display()))?;
    }
    let target = workdir.to_string_lossy().to_string();
    git(config, None, &["clone", "-q", remote, &target])?;
    Ok(())
}

/// The commit the tool's clone in `workdir` is at, as a short id.
pub fn head(workdir: &Path, config: &[(String, String)]) -> Result<String, String> {
    git(config, Some(workdir), &["rev-parse", "--short=7", "HEAD"])
}

pub fn push(plan: &Plan<'_>) -> Result<Pushed, String> {
    if plan.relative.starts_with('/') || plan.relative.split('/').any(|p| p == ".." || p.is_empty())
    {
        return Err(format!(
            "`{}` is not a path inside the repository",
            plan.relative
        ));
    }
    let dir: PathBuf = plan.workdir.to_path_buf();
    up_to_date(plan.remote, &dir, plan.git_config)?;

    let file = dir.join(plan.relative);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot make {}: {e}", parent.display()))?;
    }
    std::fs::write(&file, plan.content)
        .map_err(|e| format!("cannot write {}: {e}", file.display()))?;

    git(plan.git_config, Some(&dir), &["add", "--", plan.relative])?;
    // Exit status 0 means nothing staged differs from what the repository has.
    let unchanged = Command::new("git")
        .args(
            plan.git_config
                .iter()
                .flat_map(|(k, v)| ["-c".to_string(), format!("{k}={v}")]),
        )
        .arg("-C")
        .arg(&dir)
        .args(["diff", "--cached", "--quiet", "--", plan.relative])
        .status()
        .map_err(|e| format!("cannot run git: {e}"))?
        .success();
    if unchanged {
        return Ok(Pushed::Unchanged);
    }

    let name = format!("user.name={}", plan.author_name);
    let email = format!("user.email={}", plan.author_email);
    git(
        plan.git_config,
        Some(&dir),
        &[
            "-c",
            &name,
            "-c",
            &email,
            "commit",
            "-q",
            "-m",
            plan.message,
            "--",
            plan.relative,
        ],
    )?;
    git(
        plan.git_config,
        Some(&dir),
        &["push", "-q", "origin", "HEAD"],
    )
    .map_err(|e| {
        format!(
            "{e}; the commit is in {} and can be pushed again",
            dir.display()
        )
    })?;
    Ok(Pushed::Pushed)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Repo {
        _root: tempfile::TempDir,
        bare: PathBuf,
        work: PathBuf,
    }

    fn config() -> Vec<(String, String)> {
        // A developer's global git settings (commit signing, hooks) must not decide these tests.
        vec![
            ("commit.gpgsign".to_string(), "false".to_string()),
            ("core.hooksPath".to_string(), "/dev/null".to_string()),
            ("init.defaultBranch".to_string(), "main".to_string()),
        ]
    }

    fn repo() -> Repo {
        let root = tempfile::tempdir().unwrap();
        let bare = root.path().join("schedules.git");
        let status = Command::new("git")
            .args(["init", "-q", "--bare", "--initial-branch=main"])
            .arg(&bare)
            .status()
            .unwrap();
        assert!(status.success());
        let work = root.path().join("work/schedules");
        Repo {
            _root: root,
            bare,
            work,
        }
    }

    fn plan<'a>(
        r: &'a Repo,
        remote: &'a str,
        relative: &'a str,
        content: &'a str,
        message: &'a str,
        cfg: &'a [(String, String)],
    ) -> Plan<'a> {
        Plan {
            remote,
            workdir: &r.work,
            relative,
            content,
            message,
            author_name: "alice",
            author_email: "alice@example.org",
            git_config: cfg,
        }
    }

    fn in_remote(r: &Repo, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("--git-dir")
            .arg(&r.bare)
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn commits(r: &Repo) -> usize {
        in_remote(r, &["rev-list", "--count", "main"])
            .parse()
            .unwrap_or(0)
    }

    #[test]
    fn the_commit_message_is_a_conventional_one() {
        assert_eq!(
            message("git-repo-observer", Some("credentials"), 5, "alice"),
            "feat(git-repo-observer): credentials version 5\n\nSigned by alice with polar-sign."
        );
        assert!(
            message("git-repo-controller", None, 2, "bob")
                .starts_with("feat(git-repo-controller): settings version 2")
        );
    }

    #[test]
    fn a_document_has_a_place_per_agent_and_section() {
        assert_eq!(
            place("git-repo-observer", Some("credentials")),
            "permanent/git-repo-observer/credentials.dhall"
        );
        assert_eq!(
            place("git-repo-controller", None),
            "permanent/git-repo-controller/configuration.dhall"
        );
    }

    #[test]
    fn the_first_push_to_an_empty_repository_makes_the_file_with_the_author_and_message() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        let p = plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "signed one\n",
            "a s v1 signed by alice",
            &cfg,
        );
        assert_eq!(push(&p).unwrap(), Pushed::Pushed);
        assert_eq!(
            in_remote(&r, &["show", "main:permanent/a/s.dhall"]),
            "signed one"
        );
        assert_eq!(
            in_remote(&r, &["log", "-1", "--format=%an <%ae>|%s", "main"]),
            "alice <alice@example.org>|a s v1 signed by alice"
        );
        assert_eq!(commits(&r), 1);
    }

    /// A clone left from a repository of the same address that was made again (a cluster brought up anew) is brought up
    /// to date with what the repository holds now, whatever its own history (Vaughn's finding, 2026-11-04: `pull
    /// --ff-only` refused such a clone, "Not possible to fast-forward", and every push failed until `--workdir` was moved).
    #[test]
    fn a_clone_left_from_a_repository_made_again_is_brought_up_to_date_and_pushed_through() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        let old = plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "from the old cluster\n",
            "old",
            &cfg,
        );
        assert_eq!(push(&old).unwrap(), Pushed::Pushed);

        // The repository is made again at the same address, with a history of its own.
        std::fs::remove_dir_all(&r.bare).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "--bare", "--initial-branch=main"])
                .arg(&r.bare)
                .status()
                .unwrap()
                .success()
        );
        let other = tempfile::tempdir().unwrap();
        let elsewhere = Plan {
            workdir: other.path(),
            ..plan(
                &r,
                &remote,
                "permanent/b/t.dhall",
                "the new cluster's\n",
                "new",
                &cfg,
            )
        };
        assert_eq!(push(&elsewhere).unwrap(), Pushed::Pushed);

        let next = plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "signed now\n",
            "now",
            &cfg,
        );
        assert_eq!(push(&next).unwrap(), Pushed::Pushed);
        assert_eq!(
            in_remote(&r, &["show", "main:permanent/a/s.dhall"]),
            "signed now"
        );
        assert_eq!(
            in_remote(&r, &["show", "main:permanent/b/t.dhall"]),
            "the new cluster's"
        );
        assert_eq!(
            commits(&r),
            2,
            "the new history and this commit, nothing of the old"
        );
    }

    /// A repository made again and still empty is not given the old clone's history: the clone is made afresh.
    #[test]
    fn a_clone_left_from_a_repository_made_again_empty_is_made_afresh() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        let old = plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "from the old cluster\n",
            "old",
            &cfg,
        );
        assert_eq!(push(&old).unwrap(), Pushed::Pushed);
        std::fs::remove_dir_all(&r.bare).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q", "--bare", "--initial-branch=main"])
                .arg(&r.bare)
                .status()
                .unwrap()
                .success()
        );
        let next = plan(
            &r,
            &remote,
            "permanent/b/t.dhall",
            "first of the new\n",
            "new",
            &cfg,
        );
        assert_eq!(push(&next).unwrap(), Pushed::Pushed);
        assert_eq!(commits(&r), 1, "this commit alone");
        assert_eq!(
            in_remote(&r, &["ls-tree", "-r", "--name-only", "main"]),
            "permanent/b/t.dhall"
        );
    }

    #[test]
    fn the_same_file_again_changes_nothing() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        let p = plan(&r, &remote, "permanent/a/s.dhall", "same\n", "m", &cfg);
        assert_eq!(push(&p).unwrap(), Pushed::Pushed);
        assert_eq!(push(&p).unwrap(), Pushed::Unchanged);
        assert_eq!(commits(&r), 1);
    }

    #[test]
    fn a_new_version_replaces_the_file_in_place_and_leaves_the_others() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        push(&plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "v1\n",
            "one",
            &cfg,
        ))
        .unwrap();
        push(&plan(
            &r,
            &remote,
            "permanent/b/t.dhall",
            "other agent\n",
            "two",
            &cfg,
        ))
        .unwrap();
        push(&plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "v2\n",
            "three",
            &cfg,
        ))
        .unwrap();
        assert_eq!(in_remote(&r, &["show", "main:permanent/a/s.dhall"]), "v2");
        assert_eq!(
            in_remote(&r, &["show", "main:permanent/b/t.dhall"]),
            "other agent"
        );
        assert_eq!(commits(&r), 3);
        // git keeps the history of the first version
        assert_eq!(in_remote(&r, &["show", "main~2:permanent/a/s.dhall"]), "v1");
    }

    #[test]
    fn what_someone_else_pushed_meanwhile_is_brought_in_before_the_push() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        push(&plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "mine\n",
            "one",
            &cfg,
        ))
        .unwrap();

        // another author, in a clone of their own
        let other = r._root.path().join("other");
        assert!(
            Command::new("git")
                .args(["clone", "-q"])
                .arg(&remote)
                .arg(&other)
                .status()
                .unwrap()
                .success()
        );
        std::fs::create_dir_all(other.join("permanent/c")).unwrap();
        std::fs::write(other.join("permanent/c/u.dhall"), "theirs\n").unwrap();
        for args in [
            vec!["add", "."],
            vec![
                "-c",
                "user.name=bob",
                "-c",
                "user.email=bob@example.org",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-q",
                "-m",
                "bob",
            ],
            vec!["push", "-q", "origin", "HEAD"],
        ] {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&other)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }

        push(&plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "mine v2\n",
            "two",
            &cfg,
        ))
        .unwrap();
        assert_eq!(
            in_remote(&r, &["show", "main:permanent/c/u.dhall"]),
            "theirs"
        );
        assert_eq!(
            in_remote(&r, &["show", "main:permanent/a/s.dhall"]),
            "mine v2"
        );
        assert_eq!(commits(&r), 3);
    }

    #[test]
    fn only_the_documents_file_is_committed() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        push(&plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "v1\n",
            "one",
            &cfg,
        ))
        .unwrap();
        // something else the author left staged in the working folder
        std::fs::write(r.work.join("stray.txt"), "not for the repository\n").unwrap();
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&r.work)
                .args(["add", "stray.txt"])
                .status()
                .unwrap()
                .success()
        );
        push(&plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "v2\n",
            "two",
            &cfg,
        ))
        .unwrap();
        assert_eq!(
            in_remote(&r, &["ls-tree", "-r", "--name-only", "main"]),
            "permanent/a/s.dhall"
        );
    }

    #[test]
    fn a_working_folder_that_is_another_repositorys_is_refused() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        push(&plan(
            &r,
            &remote,
            "permanent/a/s.dhall",
            "v1\n",
            "one",
            &cfg,
        ))
        .unwrap();
        let err = push(&plan(
            &r,
            "/somewhere/else.git",
            "permanent/a/s.dhall",
            "v2\n",
            "two",
            &cfg,
        ))
        .unwrap_err();
        assert!(err.contains("another repository"), "{err}");
        assert_eq!(commits(&r), 1);
    }

    #[test]
    fn a_repository_that_cannot_be_reached_says_so_and_writes_nothing() {
        let r = repo();
        let cfg = config();
        let err = push(&plan(
            &r,
            "/no/such/repository.git",
            "permanent/a/s.dhall",
            "v1\n",
            "one",
            &cfg,
        ))
        .unwrap_err();
        assert!(err.contains("`git clone` failed"), "{err}");
        assert!(!r.work.join("permanent").exists());
    }

    #[test]
    fn a_path_that_leaves_the_repository_is_refused_before_git_is_run() {
        let r = repo();
        let cfg = config();
        let remote = r.bare.to_string_lossy().to_string();
        for bad in ["/etc/x", "../x", "permanent/../../x", "permanent//x", ""] {
            let err = push(&plan(&r, &remote, bad, "x", "m", &cfg)).unwrap_err();
            assert!(
                err.contains("is not a path inside the repository"),
                "{bad}: {err}"
            );
        }
        assert!(!r.work.exists());
    }
}
