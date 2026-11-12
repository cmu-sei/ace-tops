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

//! The checkout the watcher reads, made to hold what the git server says `main` holds (src/reads.rs): each file written
//! where it differs, and each file the answer does not hold removed, so the folder is the repository's word. A file is
//! written whole beside its place and moved there, so the watcher never reads half of one. A path that could leave the
//! folder or name git's own files is refused; a link is not made, since nothing the watcher reads is one and a link could
//! point it anywhere. What a clone left (`.git`, before the observer read over Cassini) is left alone.

use polar_git_server_common::{FileAt, FileKind};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use tracing::warn;

/// A relative path of plain segments: none empty, `.` or `..`, none `.git`, no backslash or NUL.
fn plain(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment != ".git"
                && !segment.contains(['\\', '\0'])
        })
}

/// Makes `dir` hold `files` and nothing else (but what a clone left), saying whether anything changed. What is gone goes
/// first, and a folder it leaves empty with it, so a file can take the place of a folder and a folder of a file, as a
/// commit can make them. Blocking.
pub fn apply(dir: &Path, files: &[FileAt]) -> Result<bool, String> {
    if let Some(bad) = files.iter().find(|f| !plain(&f.path)) {
        return Err(format!(
            "`{}` is not a plain path in the checkout",
            bad.path
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let mut changed = false;
    let mut written = Vec::new();
    for file in files {
        if file.kind == FileKind::Link {
            warn!(path = %file.path, "a link in the repository is not made in the checkout");
            continue;
        }
        written.push((dir.join(&file.path), file));
    }
    let kept: BTreeSet<&PathBuf> = written.iter().map(|(at, _)| at).collect();
    for gone in files_in(dir)?.into_iter().filter(|f| !kept.contains(f)) {
        std::fs::remove_file(&gone)
            .map_err(|e| format!("cannot remove {}: {e}", gone.display()))?;
        changed = true;
    }
    prune_empty(dir)?;
    for (at, file) in written {
        if std::fs::read(&at).ok().as_deref() == Some(file.content.as_slice()) {
            continue;
        }
        let parent = at.parent().expect("a file in the checkout has a folder");
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot make {}: {e}", parent.display()))?;
        let beside = parent.join(format!(
            ".{}.reading",
            at.file_name()
                .expect("a plain path names a file")
                .to_string_lossy()
        ));
        std::fs::write(&beside, &file.content)
            .and_then(|()| std::fs::rename(&beside, &at))
            .map_err(|e| format!("cannot write {}: {e}", at.display()))?;
        changed = true;
    }
    Ok(changed)
}

/// Removes every folder under `dir` that holds nothing, deepest first, but what a clone left.
fn prune_empty(dir: &Path) -> Result<(), String> {
    for entry in walkdir::WalkDir::new(dir)
        .min_depth(1)
        .contents_first(true)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        if entry.file_type().is_dir()
            && std::fs::read_dir(entry.path()).is_ok_and(|mut held| held.next().is_none())
        {
            std::fs::remove_dir(entry.path())
                .map_err(|e| format!("cannot remove {}: {e}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Every file under `dir`, but what a clone left under `.git`.
fn files_in(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        if !entry.file_type().is_dir() {
            found.push(entry.into_path());
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> FileAt {
        FileAt {
            path: path.into(),
            kind: FileKind::Plain,
            content: text.into(),
        }
    }

    fn held(dir: &Path) -> Vec<(String, String)> {
        let mut held: Vec<(String, String)> = files_in(dir)
            .unwrap()
            .into_iter()
            .map(|p| {
                (
                    p.strip_prefix(dir).unwrap().to_string_lossy().into_owned(),
                    std::fs::read_to_string(&p).unwrap(),
                )
            })
            .collect();
        held.sort();
        held
    }

    /// The checkout comes to hold what the answer holds: files written, changed and removed, nothing changed the second
    /// time, and what a clone left untouched.
    #[test]
    fn the_checkout_holds_what_main_holds_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let first = [file("permanent/a.dhall", "1"), file("README.md", "r")];
        assert!(apply(dir.path(), &first).unwrap());
        assert!(!apply(dir.path(), &first).unwrap(), "nothing to change");
        let second = [file("permanent/a.dhall", "2"), file("adhoc/b.dhall", "b")];
        assert!(apply(dir.path(), &second).unwrap());
        assert_eq!(
            held(dir.path()),
            [
                ("adhoc/b.dhall".to_string(), "b".to_string()),
                ("permanent/a.dhall".to_string(), "2".to_string()),
            ]
        );
        assert!(
            dir.path().join(".git/HEAD").exists(),
            "what a clone left stays"
        );
    }

    #[test]
    fn a_path_that_could_leave_the_checkout_is_refused_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "../x.dhall",
            "/etc/x",
            "a//b",
            "./a",
            ".git/config",
            "a/../../b",
            "",
        ] {
            assert!(
                apply(dir.path(), &[file("ok.dhall", "1"), file(bad, "x")]).is_err(),
                "{bad:?}"
            );
            assert!(held(dir.path()).is_empty(), "{bad:?}");
        }
    }

    #[test]
    fn a_link_is_not_made() {
        let dir = tempfile::tempdir().unwrap();
        let link = FileAt {
            path: "permanent/l.dhall".into(),
            kind: FileKind::Link,
            content: b"/etc/passwd".to_vec(),
        };
        apply(dir.path(), &[link]).unwrap();
        assert!(!dir.path().join("permanent/l.dhall").exists());
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        fn files() -> impl Strategy<Value = Vec<FileAt>> {
            proptest::collection::btree_map(
                proptest::collection::vec("[ab]", 1..3).prop_map(|s| s.join("/")),
                "[xy]{0,3}",
                0..5,
            )
            .prop_map(|m| m.into_iter().map(|(p, t)| file(&p, &t)).collect())
        }

        /// Paths where one is the other's folder cannot both be files in git, so one answer never holds both.
        fn tree(files: Vec<FileAt>) -> Vec<FileAt> {
            let paths: Vec<String> = files.iter().map(|f| f.path.clone()).collect();
            files
                .into_iter()
                .filter(|f| !paths.iter().any(|p| p.starts_with(&format!("{}/", f.path))))
                .collect()
        }

        proptest! {
            /// Whatever the checkout held, a file where the next answer has a folder among it, after an answer it holds
            /// exactly that answer's files.
            #[test]
            fn after_an_answer_the_checkout_holds_exactly_its_files(before in files(), after in files()) {
                let (before, after) = (tree(before), tree(after));
                let dir = tempfile::tempdir().unwrap();
                apply(dir.path(), &before).unwrap();
                apply(dir.path(), &after).unwrap();
                let mut expected: Vec<(String, String)> = after
                    .iter()
                    .map(|f| (f.path.clone(), String::from_utf8(f.content.clone()).unwrap()))
                    .collect();
                expected.sort();
                prop_assert_eq!(held(dir.path()), expected);
            }
        }
    }
}
