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

//! The smallest OCI image the seed pushes: one layer, an uncompressed tar of a few files, deterministic, so a seed run again pushes
//! the same digests.

use gitlab_seed::oci::{image, tar};

#[test]
fn a_tar_is_blocks_of_512_with_a_valid_header_per_file_and_two_empty_blocks_at_the_end() {
    let t = tar(&[("a.txt", b"hello"), ("b.txt", b"")]);
    assert_eq!(t.len() % 512, 0);
    assert_eq!(
        t.len(),
        512 + 512 + 512 + 1024,
        "a header and a block for a.txt, a header for b.txt, two empty blocks"
    );
    assert!(t[t.len() - 1024..].iter().all(|b| *b == 0));
    for header in [&t[0..512], &t[1024..1536]] {
        let stated =
            u64::from_str_radix(std::str::from_utf8(&header[148..154]).unwrap().trim(), 8).unwrap();
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        assert_eq!(stated, sum, "the header's checksum");
        assert_eq!(&header[257..262], b"ustar");
    }
    assert_eq!(&t[0..5], b"a.txt");
    assert_eq!(&t[512..517], b"hello");
}

#[test]
fn an_image_names_its_config_and_layer_by_their_digests_and_is_the_same_every_time() {
    let img = image(&[("seed.txt", b"seed")]);
    assert_eq!(img, image(&[("seed.txt", b"seed")]));
    let manifest: serde_json::Value = serde_json::from_slice(&img.manifest).unwrap();
    assert_eq!(
        manifest["mediaType"],
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(manifest["config"]["digest"], img.config_digest.as_str());
    assert_eq!(manifest["layers"][0]["digest"], img.layer_digest.as_str());
    assert_eq!(manifest["layers"][0]["size"], img.layer.len());
    let config: serde_json::Value = serde_json::from_slice(&img.config).unwrap();
    assert_eq!(
        config["rootfs"]["diff_ids"][0],
        img.layer_digest.as_str(),
        "an uncompressed layer's diff id is its digest"
    );
    assert!(img.layer_digest.starts_with("sha256:") && img.layer_digest.len() == 71);
}
