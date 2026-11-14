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

use gix::bstr::{BStr, ByteSlice};
use gix::object::tree::EntryKind;
use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use gix::refs::{FullName, Target};
use polar_git_server_common::{FileAt, FileKind};
use std::collections::HashMap;
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

/// What a read of `main` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadOfMain {
    /// `main` is `commit`, and these are its files under the paths asked for, by path.
    Files { commit: String, files: Vec<FileAt> },
    /// `main` is still the commit the reader has.
    Unchanged { commit: String },
    /// The repository has no `main` yet.
    NoMain,
    /// The files asked for are more than `limit` bytes, their paths counted; nothing was read past it.
    TooLarge { limit: usize },
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
pub fn plain_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty() && !segment.starts_with('.') && !segment.contains(['\\', '\0'])
        })
}

#[derive(Debug, Clone)]
pub struct RepoStore {
    root: PathBuf,
    /// One writer of a repository at a time, shared by every clone of the store ([`RepoStore::writing`]).
    writers: std::sync::Arc<std::sync::Mutex<HashMap<String, std::sync::Arc<Writer>>>>,
}

/// A repository's writer lock, and how many writers wait for it.
#[derive(Debug, Default)]
struct Writer {
    lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    waiting: std::sync::atomic::AtomicUsize,
}

/// A repository held by one writer, until it is dropped.
pub type Writing = tokio::sync::OwnedMutexGuard<()>;

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
        Self {
            root: root.into(),
            writers: Default::default(),
        }
    }

    /// Waits to be the one writer of `name`: a repository whose `main` a log follows is written by a push and by the
    /// store itself (a section over Cassini), and each reads `main`, appends to the log and moves `main` as one step, so
    /// the log and the repository never part (docs/architecture/record-store.md, "People's tools over Cassini"). Every
    /// writer of such a repository holds it from reading `main` until `main` has moved, or has not and the log is put
    /// back to what it holds. Taken in the order asked.
    pub async fn writing(&self, name: &str) -> Writing {
        let writer = self
            .writers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(name.to_string())
            .or_default()
            .clone();
        writer
            .waiting
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let held = writer.lock.clone().lock_owned().await;
        writer
            .waiting
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        held
    }

    /// How many writers wait for `name` ([`RepoStore::writing`]): for tests, and to say when writers queue.
    pub fn writers_waiting(&self, name: &str) -> usize {
        self.writers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(name)
            .map_or(0, |writer| {
                writer.waiting.load(std::sync::atomic::Ordering::SeqCst)
            })
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

    /// Creates an empty bare repository held to git's own rules and no more (polar-git's source code: branches may be
    /// rewritten and deleted where policy lets a person), recording `owner`, who made it, in its configuration as
    /// `polar.owner`. Built beside its place and moved there whole, so none is ever found without its owner. An existing
    /// one is left as it is.
    pub async fn create_owned(&self, name: &str, owner: &str) -> Result<Created, StoreError> {
        let path = self.path(name)?;
        let root = self.root.clone();
        let name = name.to_string();
        let owner = owner.to_string();
        blocking(move || {
            if path.join("HEAD").is_file() {
                return Ok(Created::AlreadyExisted);
            }
            std::fs::create_dir_all(&root)?;
            let building = root.join(format!(
                ".{name}.creating-{}-{}",
                std::process::id(),
                CREATING.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let built = gix::init_bare(&building)
                .map_err(failed("init"))
                .and_then(|repo| {
                    let mut file = repo
                        .config_file_mut(repo.git_dir().join("config"))
                        .map_err(failed("config"))?;
                    file.set_raw_value("polar.owner", owner.as_str())
                        .map_err(failed("config"))?;
                    file.commit().map_err(failed("config"))
                });
            let moved = built.and_then(|()| match std::fs::rename(&building, &path) {
                Ok(()) => Ok(Created::New),
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

    /// Who made the repository, as [`RepoStore::create_owned`] recorded it; none for one made otherwise.
    pub async fn owner(&self, name: &str) -> Result<Option<String>, StoreError> {
        if !self.exists(name) {
            return Err(StoreError::Missing(name.to_string()));
        }
        let path = self.path(name)?;
        blocking(move || {
            let repo = open(&path)?;
            Ok(repo
                .config_snapshot()
                .string("polar.owner")
                .map(|owner| owner.to_string()))
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
        self.write_file(name, path, content, author, message, false)
            .await
    }

    /// Puts `content` at `path` on `main` as [`RepoStore::add_file`] adds it, over a file that is there with other
    /// bytes: a signed section's next version, at its place. A file already there with these bytes is left as it is.
    pub async fn put_file(
        &self,
        name: &str,
        path: &str,
        content: &[u8],
        author: &Author<'_>,
        message: &str,
    ) -> Result<FileAdded, StoreError> {
        self.write_file(name, path, content, author, message, true)
            .await
    }

    async fn write_file(
        &self,
        name: &str,
        path: &str,
        content: &[u8],
        author: &Author<'_>,
        message: &str,
        replace: bool,
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
                        let there = tree
                            .lookup_entry_by_path(&path)
                            .map_err(failed("read tree"))?
                            .map(|entry| entry.object_id());
                        if there.is_some_and(|id| !replace || id == blob) {
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

    /// The files `main` holds under `paths` (each a file, or a directory and all under it; none, every file), unless it is
    /// still the commit `have`, or they are more than `limit` bytes, their paths counted. A submodule's commit is not a
    /// file of this repository, and is passed over.
    pub async fn read_main(
        &self,
        name: &str,
        paths: Vec<String>,
        have: Option<String>,
        limit: usize,
    ) -> Result<ReadOfMain, StoreError> {
        if !self.exists(name) {
            return Err(StoreError::Missing(name.to_string()));
        }
        let path = self.path(name)?;
        blocking(move || {
            let repo = open(&path)?;
            let Some(main) = commit_of(&repo, MAIN) else {
                return Ok(ReadOfMain::NoMain);
            };
            let commit = main.to_string();
            if have.as_deref() == Some(commit.as_str()) {
                return Ok(ReadOfMain::Unchanged { commit });
            }
            match files_of(&repo, main, &paths, limit)? {
                Some(files) => Ok(ReadOfMain::Files { commit, files }),
                None => Ok(ReadOfMain::TooLarge { limit }),
            }
        })
        .await
    }

    /// `main`'s commit, how many commits its history holds, and every file of its tree, a submodule left out; none when
    /// the repository has no `main` yet.
    pub async fn main_tree(
        &self,
        name: &str,
    ) -> Result<Option<(gix::ObjectId, u64, Vec<FileAt>)>, StoreError> {
        if !self.exists(name) {
            return Err(StoreError::Missing(name.to_string()));
        }
        let path = self.path(name)?;
        blocking(move || {
            let repo = open(&path)?;
            let Some(main) = commit_of(&repo, MAIN) else {
                return Ok(None);
            };
            let mut commits = 0u64;
            for commit in repo.rev_walk([main]).all().map_err(failed("walk"))? {
                commit.map_err(failed("walk"))?;
                commits += 1;
            }
            let files = files_of(&repo, main, &[], usize::MAX)?.unwrap_or_default();
            Ok(Some((main, commits, files)))
        })
        .await
    }

    pub async fn has_history(&self, name: &str) -> Result<bool, StoreError> {
        let path = self.path(name)?;
        blocking(move || any_ref(&open(&path)?)).await
    }
}

/// The files of `commit`'s tree under `paths` (none: every file), by path, a submodule left out; none when they are more
/// than `limit` bytes, their paths counted.
pub fn files_of(
    repo: &gix::Repository,
    commit: gix::ObjectId,
    paths: &[String],
    limit: usize,
) -> Result<Option<Vec<FileAt>>, StoreError> {
    let root = repo
        .find_commit(commit)
        .and_then(|commit| commit.tree())
        .map_err(failed("read tree"))?
        .id;
    let mut files = Vec::new();
    let mut size = 0usize;
    let mut directories = vec![(String::new(), root)];
    while let Some((directory, id)) = directories.pop() {
        let tree = repo.find_tree(id).map_err(failed("read tree"))?;
        for entry in tree.decode().map_err(failed("read tree"))?.entries {
            let name = entry
                .filename
                .to_str()
                .map_err(|_| StoreError::BadPath(format!("{directory}/{}", entry.filename)))?;
            let at = if directory.is_empty() {
                name.to_string()
            } else {
                format!("{directory}/{name}")
            };
            let kind = if entry.mode.is_tree() {
                if leads_to(&at, paths) {
                    directories.push((at, entry.oid.to_owned()));
                }
                continue;
            } else if entry.mode.is_commit() {
                continue;
            } else if entry.mode.is_link() {
                FileKind::Link
            } else if entry.mode.is_executable() {
                FileKind::Executable
            } else {
                FileKind::Plain
            };
            if !under(&at, paths) {
                continue;
            }
            let content = repo
                .find_blob(entry.oid)
                .map_err(failed("read blob"))?
                .detach()
                .data;
            size = size.saturating_add(at.len() + content.len());
            if size > limit {
                return Ok(None);
            }
            files.push(FileAt {
                path: at,
                kind,
                content,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Some(files))
}

/// Whether the file at `path` is under one of `paths`: it is one, or in a directory one names. None names every file.
fn under(path: &str, paths: &[String]) -> bool {
    paths.is_empty()
        || paths.iter().any(|p| {
            path == p
                || path
                    .strip_prefix(p.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

/// Whether the directory `directory` holds, or is under, one of `paths`.
fn leads_to(directory: &str, paths: &[String]) -> bool {
    under(directory, paths)
        || paths.iter().any(|p| {
            p.strip_prefix(directory)
                .is_some_and(|rest| rest.starts_with('/'))
        })
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

    /// A file is put over one with other bytes, and left alone over one with the same bytes; added, it is never put over.
    #[tokio::test]
    async fn a_file_is_put_over_other_bytes_and_added_only_where_none_is() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        store.create("s").await.unwrap();
        let by = Author {
            name: "alice",
            email: "alice@example.org",
        };
        let put = |text: &'static str| {
            store.put_file(
                "s",
                "permanent/a/configuration.dhall",
                text.as_bytes(),
                &by,
                "chore: a",
            )
        };
        assert!(matches!(
            put("1").await.unwrap(),
            FileAdded::Committed { .. }
        ));
        assert_eq!(put("1").await.unwrap(), FileAdded::AlreadyThere);
        assert!(matches!(
            put("2").await.unwrap(),
            FileAdded::Committed { .. }
        ));
        assert_eq!(
            store
                .add_file(
                    "s",
                    "permanent/a/configuration.dhall",
                    b"3",
                    &by,
                    "chore: a"
                )
                .await
                .unwrap(),
            FileAdded::AlreadyThere
        );
        let ReadOfMain::Files { files, .. } = store
            .read_main("s", vec![], None, usize::MAX)
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(files[0].content, b"2");
    }

    /// A repository of source code is made with its owner and without the record rules: git's own rules alone, so a
    /// branch may be rewritten or deleted where policy allows; made again, it is left as it is, its owner the first.
    #[tokio::test]
    async fn an_owned_repository_has_its_owner_and_no_record_rules() {
        let dir = tempfile::tempdir().unwrap();
        let store = RepoStore::new(dir.path());
        assert_eq!(
            store.create_owned("tools", "alice").await.unwrap(),
            Created::New
        );
        assert_eq!(
            store.create_owned("tools", "bob").await.unwrap(),
            Created::AlreadyExisted
        );
        assert_eq!(
            store.owner("tools").await.unwrap().as_deref(),
            Some("alice")
        );
        let repo = gix::open(store.path("tools").unwrap()).unwrap();
        let config = repo.config_snapshot();
        assert_eq!(config.boolean("receive.denyDeletes"), None);
        assert_eq!(config.boolean("receive.denyNonFastForwards"), None);
        store.create("records").await.unwrap();
        assert_eq!(store.owner("records").await.unwrap(), None);
        assert!(store.owner("missing").await.is_err());
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

    /// What `main` holds is read as files under the paths asked for: a path names a file or a directory, never a prefix of
    /// a name; none names every file. Each file comes with what git records it as. A reader that has `main` already is told
    /// so; a repository with no `main` says so; and what is more than the limit is not read.
    #[tokio::test]
    async fn main_is_read_as_the_files_under_the_paths_asked_for() {
        use polar_git_server_common::{FileAt, FileKind};
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tree = tempfile::tempdir().unwrap();
        for (path, text) in [
            ("a.dhall", "a"),
            ("permanent/x.dhall", "x"),
            ("permanent/y/z.dhall", "z"),
            ("permanently.dhall", "p"),
            ("run.sh", "#!/bin/sh\n"),
        ] {
            let at = tree.path().join(path);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            std::fs::write(at, text).unwrap();
        }
        std::fs::set_permissions(
            tree.path().join("run.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("a.dhall", tree.path().join("link")).unwrap();
        let store = RepoStore::new(dir.path());
        store.create("r").await.unwrap();
        store.seed("r", tree.path()).await.unwrap();
        let main = store.resolve_ref("r", "refs/heads/main").await.unwrap();
        let plain = |path: &str, text: &str| FileAt {
            path: path.into(),
            kind: FileKind::Plain,
            content: text.into(),
        };
        let read = |paths: &[&str], have: Option<&str>, limit: usize| {
            let store = store.clone();
            let paths: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
            let have = have.map(str::to_string);
            async move { store.read_main("r", paths, have, limit).await.unwrap() }
        };

        assert_eq!(
            read(&[], None, 1 << 20).await,
            ReadOfMain::Files {
                commit: main.clone(),
                files: vec![
                    plain("a.dhall", "a"),
                    FileAt {
                        path: "link".into(),
                        kind: FileKind::Link,
                        content: b"a.dhall".to_vec(),
                    },
                    plain("permanent/x.dhall", "x"),
                    plain("permanent/y/z.dhall", "z"),
                    plain("permanently.dhall", "p"),
                    FileAt {
                        path: "run.sh".into(),
                        kind: FileKind::Executable,
                        content: b"#!/bin/sh\n".to_vec(),
                    },
                ],
            }
        );
        assert_eq!(
            read(&["permanent"], None, 1 << 20).await,
            ReadOfMain::Files {
                commit: main.clone(),
                files: vec![
                    plain("permanent/x.dhall", "x"),
                    plain("permanent/y/z.dhall", "z")
                ],
            }
        );
        assert_eq!(
            read(&["permanent/x.dhall", "a.dhall"], None, 1 << 20).await,
            ReadOfMain::Files {
                commit: main.clone(),
                files: vec![plain("a.dhall", "a"), plain("permanent/x.dhall", "x")],
            }
        );
        assert_eq!(
            read(&["perm"], None, 1 << 20).await,
            ReadOfMain::Files {
                commit: main.clone(),
                files: vec![],
            },
            "a prefix of a name is not a path"
        );
        assert_eq!(
            read(&[], Some(&main), 1 << 20).await,
            ReadOfMain::Unchanged {
                commit: main.clone()
            }
        );
        assert_eq!(
            read(&[], None, 3).await,
            ReadOfMain::TooLarge { limit: 3 },
            "five bytes and more of content is past three"
        );
        store.create("empty").await.unwrap();
        assert_eq!(
            store
                .read_main("empty", vec![], None, 1 << 20)
                .await
                .unwrap(),
            ReadOfMain::NoMain
        );
        assert!(matches!(
            store.read_main("nope", vec![], None, 1 << 20).await,
            Err(StoreError::Missing(_))
        ));
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

    mod props {
        use super::super::{leads_to, under};
        use proptest::prelude::*;

        fn path() -> impl Strategy<Value = String> {
            proptest::collection::vec("[ab]{1,2}", 1..4).prop_map(|segments| segments.join("/"))
        }

        proptest! {
            /// A read never misses a file it was asked for: every directory above a wanted file is entered. And it takes
            /// none it was not: a wanted file is one asked for or under a directory asked for, segment by segment.
            #[test]
            fn a_wanted_file_is_reached_and_only_a_wanted_file_is_taken(
                file in path(),
                paths in proptest::collection::vec(path(), 0..3),
            ) {
                let wanted = under(&file, &paths);
                if wanted {
                    let segments: Vec<&str> = file.split('/').collect();
                    for depth in 1..segments.len() {
                        let directory = segments[..depth].join("/");
                        prop_assert!(leads_to(&directory, &paths), "{directory} is not entered for {file}");
                    }
                }
                let asked = paths.is_empty()
                    || paths.iter().any(|p| {
                        let p: Vec<&str> = p.split('/').collect();
                        let f: Vec<&str> = file.split('/').collect();
                        f.len() >= p.len() && f[..p.len()] == p[..]
                    });
                prop_assert_eq!(wanted, asked);
            }
        }
    }
}
