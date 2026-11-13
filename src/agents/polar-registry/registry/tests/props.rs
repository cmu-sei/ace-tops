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

//! Properties of the content store: whatever is kept reads back as it was given, and whatever it was given, changed, is
//! refused or is exactly what it was said to be.

use polar_registry::blobs::{Blobs, Expect};
use polar_registry_nix::hash::Sha256;
use proptest::collection::vec;
use proptest::prelude::*;
use std::io::Read;
use structured_zstd::decoding::StreamingDecoder;
use structured_zstd::encoding::{CompressionLevel, compress_to_vec};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn what_is_kept_reads_back_as_it_was_given(content in vec(any::<u8>(), 0..20_000), level in 1i32..6) {
        let dir = tempfile::tempdir().unwrap();
        let blobs = Blobs::open(dir.path(), level).unwrap();
        let expect = Expect { digest: Sha256::of(&content), size: content.len() as u64 };
        let blob = blobs.put_plain(&content[..], expect).unwrap();
        let mut back = Vec::new();
        StreamingDecoder::new(std::fs::File::open(blobs.file(&blob.digest)).unwrap()).read_to_end(&mut back).unwrap();
        prop_assert_eq!(back, content);
    }

    #[test]
    fn changed_zstd_is_refused_or_is_what_it_was_said_to_be(
        content in vec(any::<u8>(), 1..20_000),
        flips in vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let blobs = Blobs::open(dir.path(), 3).unwrap();
        let mut zstd = compress_to_vec(&content[..], CompressionLevel::from_level(3));
        for (at, byte) in flips {
            let at = at.index(zstd.len());
            zstd[at] = byte;
        }
        let expect = Expect { digest: Sha256::of(&content), size: content.len() as u64 };
        if let Ok(blob) = blobs.put_zstd(&zstd[..], expect) {
            let mut back = Vec::new();
            StreamingDecoder::new(std::fs::File::open(blobs.file(&blob.digest)).unwrap()).read_to_end(&mut back).unwrap();
            prop_assert_eq!(back, content);
        } else {
            prop_assert!(blobs.get(&expect.digest).unwrap().is_none());
        }
        prop_assert_eq!(std::fs::read_dir(dir.path().join("tmp")).unwrap().count(), 0);
    }
}
