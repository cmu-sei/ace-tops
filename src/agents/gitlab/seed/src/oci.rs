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

//! The smallest OCI image: one layer, an uncompressed tar of a few files, and its config and manifest. Deterministic (no times, no
//! owners), so a seed run again pushes the same digests and the registry already has them.

use serde_json::json;
use sha2::{Digest, Sha256};

pub const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const LAYER_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub config: Vec<u8>,
    pub config_digest: String,
    pub layer: Vec<u8>,
    pub layer_digest: String,
    pub manifest: Vec<u8>,
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// An octal field of `width` bytes, NUL-terminated.
fn octal(field: &mut [u8], value: u64) {
    let text = format!("{value:0width$o}\0", width = field.len() - 1);
    field.copy_from_slice(text.as_bytes());
}

/// A ustar archive of `files`, each a regular file, mode 0644, owned by 0 and dated 0.
pub fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, content) in files {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut header[100..108], 0o644);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], 0);
        octal(&mut header[124..136], content.len() as u64);
        octal(&mut header[136..148], 0);
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // The checksum is the header's bytes summed with its own field as spaces.
        header[148..156].copy_from_slice(b"        ");
        let sum: u64 = header.iter().map(|b| *b as u64).sum();
        let text = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(text.as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(content);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

pub fn image(files: &[(&str, &[u8])]) -> Image {
    let layer = tar(files);
    let layer_digest = digest(&layer);
    let config = serde_json::to_vec(&json!({
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": { "type": "layers", "diff_ids": [layer_digest] },
    }))
    .expect("a config serializes");
    let config_digest = digest(&config);
    let manifest = serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "config": { "mediaType": CONFIG_TYPE, "digest": config_digest, "size": config.len() },
        "layers": [{ "mediaType": LAYER_TYPE, "digest": layer_digest, "size": layer.len() }],
    }))
    .expect("a manifest serializes");
    Image {
        config,
        config_digest,
        layer,
        layer_digest,
        manifest,
    }
}
