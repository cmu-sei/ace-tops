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

//! The bare repositories on disk: creation, one-time seeding from a directory, and a file added as a commit of the
//! server's own (docs/architecture/git-server.md, "Inside the boundary": evidence records sent over Cassini). All of it in
//! process, with gix, on a blocking thread: no program is run.

use gix::bstr::BStr;
use gix::object::tree::EntryKind;
use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use gix::refs::{FullName, Target};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("'{0}' is not a valid repository name")]
    BadName(String),
    #[error("repository '{0}' does not exist")]
    Missing(String),
    #[error("'{0}' is not a plain path inside the repository")]
    BadPath(String),
    #[error("git {0} failed: {1}")]
    Git(&'static str, String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Created {
    New,
    AlreadyExisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seeded {
    Applied,
    /// The repository already has history; it is left alone.
    Skipped,
}

/// Who a commit of the server's own is by.
#[derive(Debug, Clone)]
pub struct Author<'a> {
    pub name: &'a str,
    pub email: &'a str,
}

/// What became of a file to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAdded {
    /// Committed on `main`: it moved from `old` (none in a repository with no commit yet) to `new`.
    Committed { old: Option<String>, new: String },
    /// `main` has a file at that path already; it is left as it is.
    AlreadyThere,
}

/// How many times an addition is tried again when `main` moved under it (a push in between).
const ADD_ATTEMPTS: usize = 5;

/// The branch every repository has.
const MAIN: &str = "refs/heads/main";

/// Who the seeding commit is by.
const SEEDER: Author<'static> = Author {
    name: "polar-git-server",
    email: "polar-git-server@localhost",
};

/// A relative path of plain segments: none empty, none starting with '.', no backslash or NUL. So it cannot leave the
/// tree, name git's own files, or mean two things.
fn plain_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty() && !segment.starts_with('.') && !segment.contains(['\\', '\0'])
        })
}

#[derive(Debug, Clone)]
pub struct RepoStore {
    root: PathBuf,
}

/// Lower-case letters, digits, '-', '_' and '.', not starting with '.', no ".." and at most 64
/// characters. Keeps a name from escaping the root or colliding with git's own files.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && !name.contains("..")
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
}

impl RepoStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Where the repository lives; its existence is not checked.
    pub fn path(&self, name: &str) -> Result<PathBuf, StoreError> {
        if !valid_name(name) {
            return Err(StoreError::BadName(name.to_string()));
        }
        Ok(self.root.join(format!("{name}.git")))
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name)
            .map(|p| p.join("HEAD").is_file())
            .unwrap_or(false)
    }

    /// Creates an empty bare repository whose branch is `main`. Idempotent. A repository is built beside its place and
    /// moved there whole, so none is ever found without the settings that hold pushes to the rules; one that is there
    /// without them (made before this was so, or by hand) is given them.
    pub async fn create(&self, name: &str) -> Result<Created, StoreError> {
        let path = self.path(name)?;
        let root = self.root.clone();
        let name = name.to_string();
        blocking(move || {
            if path.join("HEAD").is_file() {
                hold_to_the_rules(&open(&path)?)?;
                return Ok(Created::AlreadyExisted);
            }
            std::fs::create_dir_all(&root)?;
            // A name no repository can have: one may not start with '.'.
            let building = root.join(format!(
                ".{name}.creating-{}-{}",
                std::process::id(),
                CREATING.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let built = gix::init_bare(&building)
                .map_err(failed("init"))
                .and_then(|repo| hold_to_the_rules(&repo));
            let moved = built.and_then(|()| match std::fs::rename(&building, &path) {
                Ok(()) => Ok(Created::New),
                // Another creation got there first: it is the repository.
                Err(_) if path.join("HEAD").is_file() => Ok(Created::AlreadyExisted),
                Err(e) => Err(e.into()),
            });
            if building.exists() {
                let _ = std::fs::remove_dir_all(&building);
            }
            moved
        })
        .await
    }

    /// Commits the contents of `tree` as the first commit on `main`, only when the repository has
    /// no refs, so a redeployment never overwrites later edits.
    pub async fn seed(&self, name: &str, tree: &Path) -> Result<Seeded, StoreError> {
        if !self.exists(name) {
            return Err(StoreError::Missing(name.to_string()));
        }
        let path = self.path(name)?;
        let tree = tree.to_path_buf();
        blocking(move || {
            let repo = open(&path)?;
            if any_ref(&repo)? {
                return Ok(Seeded::Skipped);
            }
            let mut editor = repo
                .edit_tree(gix::ObjectId::empty_tree(repo.object_hash()))
                .map_err(failed("seed"))?;
            add_directory(&repo, &mut editor, &tree, "")?;
            let tree = editor.write().map_err(failed("seed"))?.detach();
            commit_on_main(&repo, None, tree, &SEEDER, "chore: seed from deployment")
                .map_err(|why| StoreError::Git("commit", why))?;
            Ok(Seeded::Applied)
        })
        .await
    }

    /// The commit a ref points at, if it exists.
    pub async fn resolve_ref(&self, name: &str, refname: &str) -> Option<String> {
        let path = self.path(name).ok()?;
        let refname = refname.to_string();
        blocking(move || Ok(commit_of(&open(&path)?, &refname)))
            .await
            .ok()
            .flatten()
            .map(|id| id.to_string())
    }

    /// Adds `content` at `path` on `main` as one commit by `author`, on top of what `main` holds, unless a file is at
    /// that path already. `main` is moved only from the commit read, so a push in between is never lost: the addition
    /// is made again on top of it, a few times at most. Nothing needs a working tree: the tree is edited as objects.
    pub async fn add_file(
        &self,
        name: &str,
        path: &str,
        content: &[u8],
        author: &Author<'_>,
        message: &str,
    ) -> Result<FileAdded, StoreError> {
        if !plain_path(path) {
            return Err(StoreError::BadPath(path.to_string()));
        }
        if !self.exists(name) {
            return Err(StoreError::Missing(name.to_string()));
        }
        let git_dir = self.path(name)?;
        let (path, content, message) = (path.to_string(), content.to_vec(), message.to_string());
        let (author_name, author_email) = (author.name.to_string(), author.email.to_string());
        blocking(move || {
            let author = Author {
                name: &author_name,
                email: &author_email,
            };
            let repo = open(&git_dir)?;
            let blob = repo
                .write_blob(&content)
                .map_err(failed("write blob"))?
                .detach();
            let mut last = String::new();
            for _ in 0..ADD_ATTEMPTS {
                let old = commit_of(&repo, MAIN);
                let base = match old {
                    Some(old) => {
                        let tree = repo
                            .find_commit(old)
                            .and_then(|commit| commit.tree())
                            .map_err(failed("read tree"))?;
                        if tree
                            .lookup_entry_by_path(&path)
                            .map_err(failed("read tree"))?
                            .is_some()
                        {
                            return Ok(FileAdded::AlreadyThere);
                        }
                        tree.id
                    }
                    None => gix::ObjectId::empty_tree(repo.object_hash()),
                };
                let mut editor = repo.edit_tree(base).map_err(failed("edit tree"))?;
                editor
                    .upsert(path.as_str(), EntryKind::Blob, blob)
                    .map_err(failed("edit tree"))?;
                let tree = editor.write().map_err(failed("write tree"))?.detach();
                // From exactly the commit read, or from nothing: refused if a push moved it meanwhile.
                match commit_on_main(&repo, old, tree, &author, &message) {
                    Ok(new) => {
                        return Ok(FileAdded::Committed {
                            old: old.map(|id| id.to_string()),
                            new: new.to_string(),
                        });
                    }
                    Err(why) => last = why,
                }
            }
            Err(StoreError::Git(
                "update-ref",
                format!("main kept moving: {last}"),
            ))
        })
        .await
    }

    pub async fn has_history(&self, name: &str) -> Result<bool, StoreError> {
        let path = self.path(name)?;
        blocking(move || any_ref(&open(&path)?)).await
    }
}

/// Each creation's own place to build in.
static CREATING: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Sets what holds every push to the server's rules, where it is not set: no branch is rewritten or deleted, by accident or
/// not. gix-serve holds every push to these, as git does.
fn hold_to_the_rules(repo: &gix::Repository) -> Result<(), StoreError> {
    let config = repo.config_snapshot();
    let keys = ["receive.denyNonFastForwards", "receive.denyDeletes"];
    if keys.iter().all(|key| config.boolean(*key) == Some(true)) {
        return Ok(());
    }
    let mut file = repo
        .config_file_mut(repo.git_dir().join("config"))
        .map_err(failed("config"))?;
    for key in keys {
        file.set_raw_value(key, "true").map_err(failed("config"))?;
    }
    file.commit().map_err(failed("config"))
}

/// Runs `work` on a blocking thread.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| StoreError::Git("task", e.to_string()))?
}

fn failed<E: std::fmt::Display>(what: &'static str) -> impl Fn(E) -> StoreError {
    move |e| StoreError::Git(what, e.to_string())
}

/// The repository at `path`, with its own configuration and nothing else of the host's.
fn open(path: &Path) -> Result<gix::Repository, StoreError> {
    gix::open_opts(path, gix::open::Options::isolated()).map_err(failed("open"))
}

fn any_ref(repo: &gix::Repository) -> Result<bool, StoreError> {
    let platform = repo.references().map_err(failed("for-each-ref"))?;
    let mut all = platform.all().map_err(failed("for-each-ref"))?;
    Ok(all.next().is_some())
}

/// The commit `refname` resolves to, as `git rev-parse --verify <refname>^{commit}` gives it.
fn commit_of(repo: &gix::Repository, refname: &str) -> Option<gix::ObjectId> {
    repo.rev_parse_single(format!("{refname}^{{commit}}").as_str())
        .ok()
        .map(gix::Id::detach)
}

/// Commits `tree` by `author` with `old` as its parent, and moves `main` to it only from `old` (or from nothing). Why it
/// was not moved, if it was not.
fn commit_on_main(
    repo: &gix::Repository,
    old: Option<gix::ObjectId>,
    tree: gix::ObjectId,
    author: &Author<'_>,
    message: &str,
) -> Result<gix::ObjectId, String> {
    let signature = gix::actor::Signature {
        name: author.name.into(),
        email: author.email.into(),
        time: gix::date::Time::now_local_or_utc(),
    };
    let mut time = gix::date::parse::TimeBuf::default();
    let by = signature.to_ref(&mut time);
    let new = repo
        .new_commit_as(by, by, message, tree, old)
        .map_err(|e| e.to_string())?
        .id;
    let name: FullName = MAIN.try_into().map_err(|e| format!("{e}"))?;
    repo.edit_reference(RefEdit {
        change: Change::Update {
            log: LogChange {
                mode: RefLog::AndReference,
                force_create_reflog: false,
                message: message.into(),
            },
            expected: match old {
                Some(old) => PreviousValue::MustExistAndMatch(Target::Object(old)),
                None => PreviousValue::MustNotExist,
            },
            new: Target::Object(new),
        },
        name,
        deref: false,
    })
    .map_err(|e| e.to_string())?;
    Ok(new)
}

/// Adds every file under `dir` to `editor` at `prefix`, as `git add --all` does in a work tree: each file as a blob,
/// executable or not, a symbolic link as a link, and `.git` passed over.
fn add_directory(
    repo: &gix::Repository,
    editor: &mut gix::object::tree::Editor<'_>,
    dir: &Path,
    prefix: &str,
) -> Result<(), StoreError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| StoreError::BadPath(entry.path().display().to_string()))?;
        if name == ".git" {
            continue;
        }
        let at = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type()?;
        if kind.is_dir() {
            add_directory(repo, editor, &entry.path(), &at)?;
            continue;
        }
        let (kind, bytes) = if kind.is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            let target = target
                .to_str()
                .ok_or_else(|| StoreError::BadPath(entry.path().display().to_string()))?
                .as_bytes()
                .to_vec();
            (EntryKind::Link, target)
        } else {
            (
                executable_or_not(&entry.metadata()?),
                std::fs::read(entry.path())?,
            )
        };
        let blob = repo
            .write_blob(&bytes)
            .map_err(failed("write blob"))?
            .detach();
        editor
            .upsert(BStr::new(at.as_bytes()), kind, blob)
            .map_err(failed("seed"))?;
    }
    Ok(())
}

fn executable_or_not(metadata: &std::fs::Metadata) -> EntryKind {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 != 0 {
        EntryKind::BlobExecutable
    } else {
        EntryKind::Blob
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::process::Command;

    /// Runs git against `git_dir`, with `work_tree` when given. Returns stdout.
    async fn run_git(
        git_dir: &Path,
        work_tree: Option<&Path>,
        args: &[&str],
        what: &'static str,
    ) -> Result<String, StoreError> {
        let mut cmd = Command::new("git");
        cmd.env("GIT_DIR", git_dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        if let Some(tree) = work_tree {
            cmd.env("GIT_WORK_TREE", tree).current_dir(tree);
        } else {
            cmd.current_dir(git_dir);
        }
        let out = cmd.args(args).output().await?;
        if !out.status.success() {
            return Err(StoreError::Git(
                what,
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[test]
    fn names_cannot_escape_or_collide() {
        for bad in [
            "",
            ".hidden",
            "a/b",
            "..",
            "a..b",
            "Upper",
            "a b",
            &"x".repeat(65),
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        for good in ["polar-schedules", "agent_cfg.v2", "a"] {
            assert!(valid_name(good), "{good:?}");
        }
    }

    #[tokio::test]
    async fn create_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        assert!(!store.exists("polar-schedules"));
        assert_eq!(store.create("polar-schedules").await.unwrap(), Created::New);
        assert!(store.exists("polar-schedules"));
        assert_eq!(
            store.create("polar-schedules").await.unwrap(),
            Created::AlreadyExisted
        );
    }

    /// A repository is made whole or not at all: it is built beside its place and moved there, so none is ever found
    /// without the settings that hold pushes to the rules, and none of the building is left behind. One that was left
    /// without them (made before, or by hand) gets them the next time it is created.
    #[tokio::test]
    async fn a_repository_never_exists_without_its_push_rules() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        let rules = |name: &str| {
            let repo = gix::open(store.path(name).unwrap()).unwrap();
            let config = repo.config_snapshot();
            (
                config.boolean("receive.denyDeletes"),
                config.boolean("receive.denyNonFastForwards"),
            )
        };
        assert_eq!(store.create("made").await.unwrap(), Created::New);
        assert_eq!(rules("made"), (Some(true), Some(true)));
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["made.git"], "nothing of the building is left");

        gix::init_bare(store.path("bare").unwrap()).unwrap();
        assert_eq!(rules("bare"), (None, None));
        assert_eq!(store.create("bare").await.unwrap(), Created::AlreadyExisted);
        assert_eq!(rules("bare"), (Some(true), Some(true)));
    }

    #[tokio::test]
    async fn a_bad_name_is_refused_before_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        assert!(matches!(
            store.create("../x").await,
            Err(StoreError::BadName(_))
        ));
    }

    #[tokio::test]
    async fn seeding_happens_once() {
        let dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("a.dhall"), "1").unwrap();
        let store = RepoStore::new(dir.path());
        store.create("r").await.unwrap();
        assert!(!store.has_history("r").await.unwrap());
        assert_eq!(store.seed("r", tree.path()).await.unwrap(), Seeded::Applied);
        assert!(store.has_history("r").await.unwrap());

        // A later deploy with different content leaves the history alone.
        std::fs::write(tree.path().join("b.dhall"), "2").unwrap();
        assert_eq!(store.seed("r", tree.path()).await.unwrap(), Seeded::Skipped);
        let log = run_git(
            &store.path("r").unwrap(),
            None,
            &["log", "--oneline"],
            "log",
        )
        .await
        .unwrap();
        assert_eq!(log.lines().count(), 1);
    }

    async fn show(store: &RepoStore, name: &str, spec: &str) -> String {
        run_git(&store.path(name).unwrap(), None, &["show", spec], "show")
            .await
            .unwrap()
    }

    /// A file is added as one commit on `main`, on top of what is there, and nothing else in the tree changes; the same
    /// path again is left as it is, never written over; and a repository with no commit yet gets its first.
    #[tokio::test]
    async fn a_file_is_added_as_a_commit_on_main_and_never_written_over() {
        let dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("README.md"), "records\n").unwrap();
        let store = RepoStore::new(dir.path());
        store.create("evidence").await.unwrap();
        store.seed("evidence", tree.path()).await.unwrap();
        let seeded = store
            .resolve_ref("evidence", "refs/heads/main")
            .await
            .unwrap();
        let by = Author {
            name: "polar-git-server",
            email: "polar-git-server@localhost",
        };

        let added = store
            .add_file("evidence", "t/s/aa.json", b"{\"a\":1}\n", &by, "add aa")
            .await
            .unwrap();
        let FileAdded::Committed { old, new } = &added else {
            panic!("{added:?}")
        };
        assert_eq!(old.as_deref(), Some(seeded.as_str()));
        assert_eq!(
            store
                .resolve_ref("evidence", "refs/heads/main")
                .await
                .as_ref(),
            Some(new)
        );
        assert_eq!(
            show(&store, "evidence", "main:t/s/aa.json").await,
            "{\"a\":1}\n"
        );
        assert_eq!(
            show(&store, "evidence", "main:README.md").await,
            "records\n"
        );
        assert_eq!(
            show(&store, "evidence", "--format=%s%n%an <%ae>")
                .await
                .lines()
                .take(2)
                .collect::<Vec<_>>(),
            ["add aa", "polar-git-server <polar-git-server@localhost>"]
        );
        let parent = run_git(
            &store.path("evidence").unwrap(),
            None,
            &["rev-parse", "main^"],
            "rev-parse",
        )
        .await
        .unwrap();
        assert_eq!(parent.trim(), seeded);

        // The same path again, whatever it holds: left as it is.
        assert_eq!(
            store
                .add_file("evidence", "t/s/aa.json", b"other", &by, "again")
                .await
                .unwrap(),
            FileAdded::AlreadyThere
        );
        assert_eq!(
            show(&store, "evidence", "main:t/s/aa.json").await,
            "{\"a\":1}\n"
        );
        assert_eq!(
            store
                .resolve_ref("evidence", "refs/heads/main")
                .await
                .as_ref(),
            Some(new)
        );

        // A second file goes on top of the first.
        store
            .add_file("evidence", "t/s/bb.json", b"b", &by, "add bb")
            .await
            .unwrap();
        assert_eq!(
            show(&store, "evidence", "main:t/s/aa.json").await,
            "{\"a\":1}\n"
        );
        assert_eq!(show(&store, "evidence", "main:t/s/bb.json").await, "b");

        // An empty repository: its first commit, with no parent.
        store.create("empty").await.unwrap();
        let first = store
            .add_file("empty", "x.json", b"x", &by, "first")
            .await
            .unwrap();
        assert!(
            matches!(first, FileAdded::Committed { old: None, .. }),
            "{first:?}"
        );
        assert_eq!(show(&store, "empty", "main:x.json").await, "x");
    }

    /// Additions racing each other on one repository: each moves `main` only from what it read, so one that loses is
    /// made again on top of the winner, and every file is on `main` in the end, one commit each, none lost. Each lost
    /// attempt means another addition succeeded, so as many attempts as additions always suffice.
    #[tokio::test]
    async fn additions_racing_each_other_lose_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        store.create("evidence").await.unwrap();
        let racing = (0..ADD_ATTEMPTS).map(|n| {
            let store = store.clone();
            tokio::spawn(async move {
                let by = Author {
                    name: "s",
                    email: "s@localhost",
                };
                store
                    .add_file(
                        "evidence",
                        &format!("r/{n}.json"),
                        n.to_string().as_bytes(),
                        &by,
                        "m",
                    )
                    .await
            })
        });
        for added in futures_join(racing).await {
            assert!(matches!(added, FileAdded::Committed { .. }), "{added:?}");
        }
        for n in 0..ADD_ATTEMPTS {
            assert_eq!(
                show(&store, "evidence", &format!("main:r/{n}.json")).await,
                n.to_string()
            );
        }
        let count = run_git(
            &store.path("evidence").unwrap(),
            None,
            &["rev-list", "--count", "main"],
            "rev-list",
        )
        .await
        .unwrap();
        assert_eq!(count.trim(), ADD_ATTEMPTS.to_string());
    }

    async fn futures_join(
        tasks: impl Iterator<Item = tokio::task::JoinHandle<Result<FileAdded, StoreError>>>,
    ) -> Vec<FileAdded> {
        let mut out = Vec::new();
        for task in tasks.collect::<Vec<_>>() {
            out.push(task.await.unwrap().unwrap());
        }
        out
    }

    /// A path that could escape the tree, or is not a plain relative path, is refused before git is asked.
    #[tokio::test]
    async fn a_path_outside_the_tree_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        store.create("evidence").await.unwrap();
        let by = Author {
            name: "s",
            email: "s@localhost",
        };
        for bad in [
            "",
            "/abs.json",
            "a/../b.json",
            "a//b.json",
            "./a.json",
            "a/",
            ".git/config",
        ] {
            assert!(
                matches!(
                    store.add_file("evidence", bad, b"x", &by, "m").await,
                    Err(StoreError::BadPath(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn seeding_a_missing_repository_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        assert!(matches!(
            store.seed("nope", dir.path()).await,
            Err(StoreError::Missing(_))
        ));
    }
}
