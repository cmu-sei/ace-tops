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

//! A git dependency as a build's pod gets it (docs/architecture/build-orchestrator.md, D3a): a shallow bare repository
//! holding the commit its lock pins and nothing of its history, which Cargo's source replacement points the dependency's git
//! source at. Cargo then checks the commit out itself and reads its workspace as it reads any, `workspace = true` fields
//! included, so no `Cargo.toml` is read or rewritten here or in the pod.
//!
//! The repository is a gzipped tar of what a bare repository needs: `HEAD` naming `refs/heads/polar`, that ref at the commit,
//! `shallow` naming it (its parents are not there), a `config`, and one pack of the commit, its tree and their blobs with the
//! pack's index, made with libgit2's pack builder and indexer. Deterministic as a source's archive is: one thread packs, and
//! every entry has the commit's time and owner 0. Past `bound` bytes it is refused.

use flate2::{Compression, GzBuilder};
use git2::{Buf, Indexer, Oid, Repository};
use std::io::Write;
use std::path::Path;
use tar::{EntryType, Header};

/// The one ref the repository has.
pub const REF: &str = "refs/heads/polar";

/// The shallow repository of `commit` in `repository`, as a gzipped tar, at most `bound` bytes.
pub fn repository(repository: &Repository, commit: &str, bound: usize) -> Result<Vec<u8>, String> {
    let oid =
        Oid::from_str(commit).map_err(|_| format!("the repository has no commit {commit}"))?;
    let found = repository
        .find_commit(oid)
        .map_err(|_| format!("the repository has no commit {oid}"))?;
    let time = u64::try_from(found.time().seconds()).unwrap_or(0);
    let mut builder = repository
        .packbuilder()
        .map_err(|e| e.message().to_string())?;
    builder.set_threads(1);
    builder
        .insert_commit(oid)
        .map_err(|e| e.message().to_string())?;
    let mut pack = Buf::new();
    builder
        .write_buf(&mut pack)
        .map_err(|e| e.message().to_string())?;
    if pack.len() > bound {
        return Err(format!(
            "the dependency is larger than its bound ({bound} bytes)"
        ));
    }
    // The pack's index, by libgit2's indexer, in a directory of the clone's own, removed after.
    let work = repository.path().join("polar-shallow");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let indexed = (|| -> Result<(String, Vec<u8>, Vec<u8>), String> {
        // Not checked for connectivity: a shallow pack lacks the commit's parents, as it should. Each object is still checked
        // against its own id as it is indexed.
        let mut indexer =
            Indexer::new(None, &work, 0o644, false).map_err(|e| e.message().to_string())?;
        indexer.write_all(&pack).map_err(|e| e.to_string())?;
        let name = indexer.commit().map_err(|e| e.message().to_string())?;
        let read = |ext: &str| {
            std::fs::read(work.join(format!("pack-{name}.{ext}"))).map_err(|e| e.to_string())
        };
        Ok((name.clone(), read("pack")?, read("idx")?))
    })();
    let _ = std::fs::remove_dir_all(&work);
    let (name, pack, index) = indexed?;
    let files: Vec<(String, Vec<u8>)> = vec![
        ("HEAD".into(), format!("ref: {REF}\n").into_bytes()),
        (
            "config".into(),
            b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n".to_vec(),
        ),
        (REF.into(), format!("{oid}\n").into_bytes()),
        ("shallow".into(), format!("{oid}\n").into_bytes()),
        (format!("objects/pack/pack-{name}.idx"), index),
        (format!("objects/pack/pack-{name}.pack"), pack),
    ];
    let directories = [
        "objects",
        "objects/info",
        "objects/pack",
        "refs",
        "refs/heads",
        "refs/tags",
    ];
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    let mut tar = tar::Builder::new(gzip);
    let header = |kind: EntryType, mode: u32, size: u64| {
        let mut header = Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_size(size);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(time);
        header
    };
    for directory in directories {
        tar.append_data(
            &mut header(EntryType::Directory, 0o755, 0),
            Path::new(directory),
            std::io::empty(),
        )
        .map_err(|e| e.to_string())?;
    }
    for (path, bytes) in &files {
        tar.append_data(
            &mut header(EntryType::Regular, 0o644, bytes.len() as u64),
            Path::new(path),
            bytes.as_slice(),
        )
        .map_err(|e| e.to_string())?;
    }
    let bytes = tar
        .into_inner()
        .and_then(|gzip| gzip.finish())
        .map_err(|e| e.to_string())?;
    if bytes.len() > bound {
        return Err(format!(
            "the dependency is larger than its bound ({bound} bytes)"
        ));
    }
    Ok(bytes)
}
