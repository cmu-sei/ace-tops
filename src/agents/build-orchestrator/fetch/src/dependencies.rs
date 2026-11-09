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

//! A build's dependencies laid out for Cargo (docs/architecture/build-orchestrator.md, D3b), each from Polar's registry by
//! its digest, as the source is: the index the orchestrator was told, then each crate unpacked into its own directory of
//! the vendor directory with nixpkgs' minimal `.cargo-checksum.json`, each git dependency (a shallow repository of the commit
//! its lock pins) beside them, and Cargo's source replacement written into the build's Cargo home: crates.io by the vendor
//! directory, each git source, keyed as the lock names it, by its repository. Cargo checks each crate's checksum against the
//! lock again as it builds.
//!
//! The index is the orchestrator's, read by the digest it was told, and still each value in it is held to what it may be
//! before it becomes a path or a line of the configuration: a name or version that is not one, a digest that is not one, a
//! source that is not an https address, or a git query other than one `branch`, `tag` or `rev`, is refused.

use crate::{FetchError, MAX_ARCHIVE, blob_url, fetch, unpack, unpack_under};
use serde::Deserialize;
use std::path::Path;

/// The largest index read.
pub const MAX_INDEX: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    crates: Vec<IndexCrate>,
    git: Vec<IndexGit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexCrate {
    name: String,
    version: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexGit {
    source: String,
    url: String,
    commit: String,
    #[allow(dead_code)]
    packages: Vec<(String, String)>,
    digest: String,
}

fn refused(why: impl Into<String>) -> FetchError {
    FetchError::Dependencies(why.into())
}

fn is_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

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

/// Text that may stand in a TOML basic string as it is: no quote, no backslash, no control character.
fn is_plain(text: &str) -> bool {
    !text.contains(['"', '\\']) && !text.chars().any(char::is_control)
}

/// An https address of a host, with no login in it, plain.
fn is_https(url: &str) -> bool {
    url.strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|host| !host.is_empty() && !host.contains('@'))
        && is_plain(url)
}

/// A git source as Cargo's source replacement names it: its address, and what it names of the repository.
struct GitSourceOf<'a> {
    url: &'a str,
    /// `branch`, `tag` or `rev`, and its value; none, the repository's default branch.
    named: Option<(&'a str, &'a str)>,
}

/// A git source's address and what it names of the repository.
fn git_source(source: &str) -> Result<GitSourceOf<'_>, FetchError> {
    let locator = source
        .strip_prefix("git+")
        .ok_or_else(|| refused("a git dependency's source is not one"))?;
    let (url, query) = match locator.split_once('?') {
        Some((url, query)) => (url, Some(query)),
        None => (locator, None),
    };
    let named = match query {
        None => None,
        Some(query) => match query.split_once('=') {
            Some((key, value))
                if matches!(key, "branch" | "tag" | "rev")
                    && !value.is_empty()
                    && value.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')
                    }) =>
            {
                Some((key, value))
            }
            _ => {
                return Err(refused(
                    "a git dependency's source names more than a branch, a tag or a revision",
                ));
            }
        },
    };
    if !is_https(url) {
        return Err(refused("a git dependency's source is not an https address"));
    }
    Ok(GitSourceOf { url, named })
}

/// What was laid out: how many crates and git dependencies.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Laid {
    pub crates: usize,
    pub git: usize,
}

/// Lays out under `root` the dependencies whose index is `index` (`host/repository@sha256:<hex>`), and Cargo's configuration
/// for them. With no index, the configuration alone, crates.io replaced by an empty vendor directory: a build given no
/// dependencies has none to reach.
pub async fn lay_out(
    client: &reqwest::Client,
    index: Option<&str>,
    insecure: bool,
    root: &Path,
) -> Result<Laid, FetchError> {
    let vendor = root.join("vendor");
    let git_dir = root.join("git");
    let cargo = root.join("cargo");
    for dir in [&vendor, &git_dir, &cargo] {
        std::fs::create_dir_all(dir)?;
    }
    let mut config = format!(
        "# Written by build-fetch: every dependency this build is given, by digest (docs/architecture/build-orchestrator.md, D3).\n\
         [source.crates-io]\nreplace-with = \"polar-vendored\"\n\n[source.polar-vendored]\ndirectory = \"{}\"\n",
        vendor.display()
    );
    let mut laid = Laid::default();
    if let Some(index) = index {
        let url = blob_url(index, insecure)?;
        let (name, hex) = index
            .rsplit_once("@sha256:")
            .ok_or_else(|| FetchError::Unpinned(index.to_string()))?;
        let file = root.join(".polar-index.json");
        fetch(client, &url, hex, MAX_INDEX, &file).await?;
        let read: Index = serde_json::from_slice(&std::fs::read(&file)?)
            .map_err(|_| refused("the dependencies' index is not one"))?;
        let _ = std::fs::remove_file(&file);
        let blob = |sha256: &str| blob_url(&format!("{name}@sha256:{sha256}"), insecure);
        for c in &read.crates {
            if !is_name(&c.name) || !is_version(&c.version) || !is_hex(&c.sha256, 64) {
                return Err(refused(
                    "a crate in the index is not named and pinned as one is",
                ));
            }
            let top = format!("{}-{}", c.name, c.version);
            let archive = root.join(".polar-crate.tar.gz");
            fetch(client, &blob(&c.sha256)?, &c.sha256, MAX_ARCHIVE, &archive).await?;
            let unpacked = unpack_under(&archive, &vendor, Some(&top));
            let _ = std::fs::remove_file(&archive);
            unpacked?;
            std::fs::write(
                vendor.join(&top).join(".cargo-checksum.json"),
                format!("{{\"files\":{{}},\"package\":\"{}\"}}", c.sha256),
            )?;
            laid.crates += 1;
        }
        for (i, g) in read.git.iter().enumerate() {
            let hex = g
                .digest
                .strip_prefix("sha256:")
                .filter(|hex| is_hex(hex, 64))
                .ok_or_else(|| {
                    refused("a git dependency in the index is not pinned by its digest")
                })?;
            if !is_hex(&g.commit, 40) {
                return Err(refused(
                    "a git dependency in the index is not pinned to a commit",
                ));
            }
            let GitSourceOf { url, named } = git_source(&g.source)?;
            if url != g.url || !is_plain(&g.source) {
                return Err(refused(
                    "a git dependency's source and address do not agree",
                ));
            }
            let repository = git_dir.join(format!("{i}.git"));
            std::fs::create_dir_all(&repository)?;
            let archive = root.join(".polar-git.tar.gz");
            fetch(client, &blob(hex)?, hex, MAX_ARCHIVE, &archive).await?;
            let unpacked = unpack(&archive, &repository);
            let _ = std::fs::remove_file(&archive);
            unpacked?;
            let mut section = format!("\n[source.\"{}\"]\ngit = \"{url}\"\n", g.source);
            if let Some((key, value)) = named {
                section.push_str(&format!("{key} = \"{value}\"\n"));
            }
            section.push_str(&format!(
                "replace-with = \"polar-git-{i}\"\n\n[source.polar-git-{i}]\ngit = \"file://{}\"\n",
                repository.display()
            ));
            config.push_str(&section);
            laid.git += 1;
        }
    }
    std::fs::write(cargo.join("config.toml"), config)?;
    Ok(laid)
}
