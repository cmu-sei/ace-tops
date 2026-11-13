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

//! Nix's formats, as Polar's registry reads and writes them (docs/plans/registry/nix-cache.md): store paths and Nix's
//! base-32 spelling of hashes, the archive Nix moves a store path's files in (a NAR), the narinfo a binary cache answers
//! for a path, and the Ed25519 signatures on it. Each is held to Nix itself (`tests/nix.rs`): what Nix writes, this
//! reads, and what this writes is what Nix writes for the same input.
//!
//! Written for Polar rather than taken from a library: `nix-compat` (snix) is GPL-3.0, and harmonia's crates (MIT, read
//! for reference) are not published and bring their own cryptography and web stack.

pub mod hash;
pub mod nar;
pub mod narinfo;
pub mod nix32;
pub mod signature;
pub mod store_path;

/// The one store directory Polar's cache serves, and the only one a store path here may be in.
pub const STORE_DIR: &str = "/nix/store";

/// Why something is not what a Nix format says it must be.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("not Nix's base-32: {0}")]
    Nix32(String),
    #[error("not a hash Nix writes: {0}")]
    Hash(String),
    #[error("not a store path: {0}")]
    StorePath(String),
    #[error("not a NAR: {0}")]
    Nar(String),
    #[error("not a narinfo: {0}")]
    NarInfo(String),
    #[error("not a key or signature Nix writes: {0}")]
    Signature(String),
}
