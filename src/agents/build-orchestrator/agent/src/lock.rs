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

//! A build's dependencies, read from its `Cargo.lock` (docs/architecture/build-orchestrator.md, D1): each crate from crates.io
//! by the sha256 the lock pins, each git dependency by the commit it pins, so the orchestrator can fetch them through its
//! handlers and the build's pod builds offline (decision 1, carried to dependencies).
//!
//! The lock is the repository's, foreign input, so it is read as Cargo writes it and nothing else: a `version` line, then
//! `[[package]]` tables of `name`, `version`, `source`, `checksum` and `dependencies`, each a plain string (no escape, no
//! control character) or a list of them, one to a line. Anything else is refused by its line, and so is anything not pinned:
//! a crates.io crate with no checksum, another registry, a git source with no commit. A problem never repeats what the lock
//! said. A package with no source is the workspace's own and is not a dependency to fetch.

/// The largest lock read, and the most packages in it.
pub const MAX_LOCK: usize = 16 * 1024 * 1024;
pub const MAX_PACKAGES: usize = 20_000;

/// crates.io, as a lock names it: the git index, or the sparse one.
const CRATES_IO: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// A crate from crates.io.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Crate {
    pub name: String,
    pub version: String,
    /// Its `.crate` file's sha256, lower-case hex: what crates.io serves must be it.
    pub sha256: String,
}

/// A git repository at one commit, and the packages of it the build uses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitSource {
    /// The source as the lock names it, without the commit: what Cargo's source replacement is keyed by.
    pub source: String,
    /// The repository's https address.
    pub url: String,
    pub commit: String,
    /// Each package of it, by name and version.
    pub packages: Vec<(String, String)>,
}

/// What a build depends on, outside its own workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dependencies {
    pub crates: Vec<Crate>,
    pub git: Vec<GitSource>,
}

#[derive(Default)]
struct Package {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
    /// The line its table starts on.
    line: usize,
}

/// A plain string as Cargo writes one: quoted, with no `"`, `\` or control character inside.
fn plain(text: &str) -> Option<&str> {
    let inner = text.strip_prefix('"')?.strip_suffix('"')?;
    (!inner.contains(['"', '\\']) && !inner.chars().any(char::is_control)).then_some(inner)
}

/// A crate's name, which becomes a directory's: letters, digits, `_` and `-`.
fn is_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A version, which becomes part of a directory's name: letters, digits, `.`, `+` and `-`, and not `.` or `..`.
fn is_version(version: &str) -> bool {
    (1..=64).contains(&version.len())
        && version != "."
        && version != ".."
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'+' || b == b'-')
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The dependencies `lock` pins, or every problem with it, each by its line or package.
pub fn read(lock: &str) -> Result<Dependencies, Vec<String>> {
    if lock.len() > MAX_LOCK {
        return Err(vec![format!("the lock is larger than {MAX_LOCK} bytes")]);
    }
    let mut problems = Vec::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut in_list = false;
    let mut seen_version = false;
    for (n, line) in lock.split('\n').enumerate() {
        let at = n + 1;
        if in_list {
            if line == "]" {
                in_list = false;
            } else if !line
                .strip_prefix(' ')
                .and_then(|l| l.strip_suffix(','))
                .is_some_and(|l| plain(l).is_some())
            {
                problems.push(format!(
                    "line {at}: not a dependency's name, as Cargo writes one"
                ));
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[package]]" {
            if packages.len() == MAX_PACKAGES {
                problems.push(format!("the lock has more than {MAX_PACKAGES} packages"));
                break;
            }
            packages.push(Package {
                line: at,
                ..Package::default()
            });
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            problems.push(format!("line {at}: not what Cargo writes in a lock"));
            continue;
        };
        let Some(package) = packages.last_mut() else {
            if key == "version"
                && !seen_version
                && value.bytes().all(|b| b.is_ascii_digit())
                && !value.is_empty()
            {
                seen_version = true;
            } else {
                problems.push(format!(
                    "line {at}: not what Cargo writes before a lock's packages"
                ));
            }
            continue;
        };
        if key == "dependencies" {
            if value == "[" {
                in_list = true;
            } else if value != "[]" {
                problems.push(format!(
                    "line {at}: a package's dependencies are a list, one to a line"
                ));
            }
            continue;
        }
        let slot = match key {
            "name" => &mut package.name,
            "version" => &mut package.version,
            "source" => &mut package.source,
            "checksum" => &mut package.checksum,
            _ => {
                problems.push(format!("line {at}: not a key of a package"));
                continue;
            }
        };
        match plain(value) {
            Some(text) if slot.is_none() => *slot = Some(text.to_string()),
            Some(_) => problems.push(format!("line {at}: `{key}` is given twice")),
            None => problems.push(format!("line {at}: `{key}` is not a plain string")),
        }
    }
    if in_list {
        problems.push("the lock ends inside a list".to_string());
    }
    let mut dependencies = Dependencies::default();
    for package in &packages {
        let at = package.line;
        let (Some(name), Some(version)) = (&package.name, &package.version) else {
            problems.push(format!(
                "the package at line {at} has no name or no version"
            ));
            continue;
        };
        if !is_name(name) || !is_version(version) {
            problems.push(format!(
                "the package at line {at} has a name or version that is not one"
            ));
            continue;
        }
        let Some(source) = &package.source else {
            // The workspace's own, or a path dependency: built from the source itself.
            continue;
        };
        if CRATES_IO.contains(&source.as_str()) {
            match &package.checksum {
                Some(sum) if is_hex(sum, 64) => dependencies.crates.push(Crate {
                    name: name.clone(),
                    version: version.clone(),
                    sha256: sum.clone(),
                }),
                Some(_) => problems.push(format!("{name} {version}: its checksum is not a sha256")),
                None => problems.push(format!("{name} {version}: it is not pinned by a checksum")),
            }
        } else if let Some(git) = source.strip_prefix("git+") {
            let Some((locator, commit)) = git.rsplit_once('#') else {
                problems.push(format!(
                    "{name} {version}: its git source is not pinned to a commit"
                ));
                continue;
            };
            let url = locator.split_once('?').map_or(locator, |(url, _)| url);
            if !is_hex(commit, 40) {
                problems.push(format!(
                    "{name} {version}: its git source is not pinned to a commit"
                ));
            } else if git_agent_common::remote::https_host(url).is_err() {
                problems.push(format!(
                    "{name} {version}: its git source is not an https address of a host"
                ));
            } else {
                let source = format!("git+{locator}");
                match dependencies
                    .git
                    .iter_mut()
                    .find(|g| g.source == source && g.commit == commit)
                {
                    Some(held) => held.packages.push((name.clone(), version.clone())),
                    None => dependencies.git.push(GitSource {
                        source,
                        url: url.to_string(),
                        commit: commit.to_string(),
                        packages: vec![(name.clone(), version.clone())],
                    }),
                }
            }
        } else {
            problems.push(format!(
                "{name} {version}: its source is neither crates.io nor a git repository"
            ));
        }
    }
    dependencies.crates.sort();
    let before = dependencies.crates.len();
    dependencies.crates.dedup();
    if dependencies.crates.len() != before {
        problems.push("a crate is named twice".to_string());
    }
    for git in &mut dependencies.git {
        git.packages.sort();
    }
    dependencies.git.sort();
    if problems.is_empty() {
        Ok(dependencies)
    } else {
        Err(problems)
    }
}

/// What several locks pin, together: each crate once, and each git source's packages together, in the order `read` gives.
pub fn union(parts: Vec<Dependencies>) -> Dependencies {
    let mut all = Dependencies::default();
    for part in parts {
        all.crates.extend(part.crates);
        for git in part.git {
            match all
                .git
                .iter_mut()
                .find(|held| held.source == git.source && held.commit == git.commit)
            {
                Some(held) => held.packages.extend(git.packages),
                None => all.git.push(git),
            }
        }
    }
    all.crates.sort();
    all.crates.dedup();
    for git in &mut all.git {
        git.packages.sort();
        git.packages.dedup();
    }
    all.git.sort();
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Polar's own lock, as Cargo wrote it: read whole, every crates.io checksum in it read, every git source pinned.
    #[test]
    fn polars_own_lock_is_read() {
        let text = include_str!("../../../Cargo.lock");
        let read = read(text).unwrap();
        let sums: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("checksum = \"")?.strip_suffix('"'))
            .collect();
        assert_eq!(read.crates.len(), sums.len());
        for sum in sums {
            assert!(read.crates.iter().any(|c| c.sha256 == sum));
        }
        let git_lines = text
            .lines()
            .filter(|l| l.starts_with("source = \"git+"))
            .count();
        assert_eq!(
            read.git.iter().map(|g| g.packages.len()).sum::<usize>(),
            git_lines
        );
    }
}
