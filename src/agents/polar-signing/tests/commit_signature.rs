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

//! A deployment commit's signature, against a real commit that `deploy-repo.nu publish` signed with `gpgsm` (tests/fixtures: the commit
//! and the public certificate of the CA it chains to; no key).

use polar_signing::commit::{CommitError, verify_commit};
use polar_signing::verify::VerifyError;
use polar_signing::{Trust, testing};
use proptest::prelude::*;

const COMMIT: &[u8] = include_bytes!("fixtures/deploy-commit.raw");
const CA: &str = include_str!("fixtures/deploy-ca.pem");
/// When the fixture was signed: the certificates are valid then, whatever today is.
const SIGNED_AT: i64 = 1793659810;

fn trust() -> Trust {
    Trust::from_pem(&[CA.to_string()]).unwrap()
}

/// Where the signature's base64 lines are in the commit, and where the message starts.
fn spans() -> (std::ops::Range<usize>, usize) {
    let text = std::str::from_utf8(COMMIT).unwrap();
    let start = text.find("gpgsig ").unwrap();
    let end = text.find("-----END SIGNED MESSAGE-----").unwrap();
    let message = text.find("\n\n").unwrap() + 2;
    (start..end, message)
}

#[test]
fn a_commit_the_pipeline_signed_is_believed() {
    let signer = verify_commit(COMMIT, &trust(), "pipeline", SIGNED_AT).unwrap();
    assert!(!signer.serial.is_empty());
}

#[test]
fn a_changed_message_is_refused() {
    let mut changed = COMMIT.to_vec();
    let (_, message) = spans();
    changed[message] ^= 0x01;
    assert!(matches!(
        verify_commit(&changed, &trust(), "pipeline", SIGNED_AT),
        Err(CommitError::DigestMismatch)
    ));
}

#[test]
fn a_changed_tree_is_refused() {
    // The tree is what is deployed: `tree ` and a digit of its hash.
    let mut changed = COMMIT.to_vec();
    changed[5] = if changed[5] == b'0' { b'1' } else { b'0' };
    assert!(matches!(
        verify_commit(&changed, &trust(), "pipeline", SIGNED_AT),
        Err(CommitError::DigestMismatch)
    ));
}

#[test]
fn an_unsigned_commit_is_refused() {
    let text = std::str::from_utf8(COMMIT).unwrap();
    let (signature, _) = spans();
    let end = text[signature.end..].find('\n').unwrap() + signature.end + 1;
    let unsigned = format!("{}{}", &text[..signature.start], &text[end..]);
    assert!(matches!(
        verify_commit(unsigned.as_bytes(), &trust(), "pipeline", SIGNED_AT),
        Err(CommitError::Unsigned)
    ));
}

#[test]
fn another_ca_is_refused() {
    let other = testing::root("someone-else").pem;
    let trust = Trust::from_pem(&[other]).unwrap();
    assert!(matches!(
        verify_commit(COMMIT, &trust, "pipeline", SIGNED_AT),
        Err(CommitError::Verify(VerifyError::UntrustedRoot))
    ));
}

#[test]
fn another_signer_of_the_same_ca_is_refused() {
    assert!(matches!(
        verify_commit(COMMIT, &trust(), "flux", SIGNED_AT),
        Err(CommitError::WrongSigner { .. })
    ));
}

#[test]
fn a_certificate_that_is_not_valid_now_is_refused() {
    let before = 1_000_000_000;
    let after = 4_000_000_000;
    for now in [before, after] {
        assert!(matches!(
            verify_commit(COMMIT, &trust(), "pipeline", now),
            Err(CommitError::Verify(VerifyError::NotValidNow(_)))
        ));
    }
}

/// Every byte, not a sample: the signature holds parts nothing signs (its wrapping, its algorithm lists), and those are checked too.
#[test]
fn no_byte_of_the_commit_can_change() {
    let trust = trust();
    let mut believed = Vec::new();
    for at in 0..COMMIT.len() {
        for flip in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80] {
            let mut changed = COMMIT.to_vec();
            changed[at] ^= flip;
            if verify_commit(&changed, &trust, "pipeline", SIGNED_AT).is_ok() {
                believed.push((at, flip));
            }
        }
    }
    assert_eq!(believed, [], "bytes changed and still believed");
}

proptest! {
    /// Anything that is not the commit as signed is refused, wherever the change falls: its headers, its message or its signature.
    #[test]
    fn no_changed_byte_is_believed(at in 0..COMMIT.len(), flip in 1u8..=255) {
        let mut changed = COMMIT.to_vec();
        changed[at] ^= flip;
        prop_assert!(verify_commit(&changed, &trust(), "pipeline", SIGNED_AT).is_err());
    }

    #[test]
    fn what_is_not_a_commit_never_panics_and_is_refused(junk in prop::collection::vec(any::<u8>(), 0..512)) {
        prop_assert!(verify_commit(&junk, &trust(), "pipeline", SIGNED_AT).is_err());
    }

    /// A signature cut short, wherever it is cut, does not read, and does not panic.
    #[test]
    fn a_truncated_commit_is_refused(keep in 0..COMMIT.len()) {
        prop_assert!(verify_commit(&COMMIT[..keep], &trust(), "pipeline", SIGNED_AT).is_err());
    }
}
