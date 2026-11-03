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

//! A deployment commit's signature, read the way `git verify-commit` and `gpgsm` would, with neither on the machine
//! (docs/architecture/cluster-bootstrap.md, "Handing off to Polar's git server").
//!
//! `deploy-repo.nu publish` signs with git's x509 support: the commit's `gpgsig` header holds a detached CMS `SignedData`
//! over the commit without that header. `gpgsm` writes it in BER with indefinite lengths, so it is walked with a BER parser
//! and not a DER one. What is signed is the attributes, whose `messageDigest` is the commit's: a commit is believed only if that
//! digest is its own, the signature over the attributes verifies with the signer's key, and the signer chains to a pinned CA.

use crate::cert;
use crate::document::Algorithm;
use crate::verify::{MAX_CHAIN, SignerInfo, Trust, VerifyError, issued_by, signer_info, valid_at};
use base64::Engine;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;

/// The DER of `1.2.840.113549.1.7.2`, `signedData`.
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// `1.2.840.113549.1.7.1`, `data`: what a detached signature says it is over.
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// `1.2.840.113549.1.9.3`, the attribute `contentType`.
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// `1.2.840.113549.1.9.4`, the attribute `messageDigest`.
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// The whole AlgorithmIdentifier of SHA-256, with its NULL parameters, as `gpgsm` writes it.
const SHA256: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
];
/// The whole AlgorithmIdentifier of `ecdsa-with-SHA256`, as `gpgsm` writes it: with NULL parameters, which RFC 5758 would omit.
const ECDSA_SHA256: &[u8] = &[
    0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00,
];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xa0;

/// How deep the wrapping of a signature may go.
const MAX_DEPTH: usize = 8;

/// Why a deployment commit is not believed.
#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    #[error("the commit has no signature")]
    Unsigned,
    #[error("the commit's signature does not read: {0}")]
    Malformed(String),
    #[error("the commit was signed with an algorithm this verifier does not take: {0}")]
    UnsupportedAlgorithm(String),
    #[error("the signature's digest is not this commit's")]
    DigestMismatch,
    #[error("the commit was signed by `{found}`, not `{expected}`")]
    WrongSigner { expected: String, found: String },
    #[error(transparent)]
    Verify(#[from] VerifyError),
}

/// Checks a commit, in the form `git cat-file commit` gives it: signed by the certificate named `signer` (its common name), chaining
/// to `trust` at `now`. Says who signed.
pub fn verify_commit(
    raw: &[u8],
    trust: &Trust,
    signer: &str,
    now: i64,
) -> Result<SignerInfo, CommitError> {
    let (payload, encoded) = split(raw)?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .map_err(|e| malformed(&format!("its base64: {e}")))?;
    let signed = read_signed_data(&der)?;

    let digest = Sha256::digest(&payload);
    if signed.message_digest != &digest[..] {
        return Err(CommitError::DigestMismatch);
    }

    let certs = signed
        .certificates
        .iter()
        .map(|der| cert::parse(der).map_err(VerifyError::BadCertificate))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = certs
        .iter()
        .find(|c| {
            c.tbs_certificate.raw_serial() == signed.serial && c.issuer().as_raw() == signed.issuer
        })
        .ok_or_else(|| malformed("it does not carry the certificate that signed it"))?;
    chain_to_a_pin(leaf, &certs, trust, now)?;

    let found = leaf
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .unwrap_or_default();
    if found != signer {
        return Err(CommitError::WrongSigner {
            expected: signer.to_string(),
            found: found.to_string(),
        });
    }
    if let Ok(Some(usage)) = leaf.key_usage()
        && !usage.value.digital_signature()
    {
        return Err(VerifyError::KeyUsage.into());
    }
    let Some((Algorithm::EcdsaP256Sha256, key)) = cert::key_of(leaf) else {
        return Err(CommitError::UnsupportedAlgorithm(
            leaf.public_key().algorithm.algorithm.to_id_string(),
        ));
    };

    // What is signed is the attributes as a SET, though they are written with a context tag.
    let mut attributes = vec![TAG_SET];
    attributes.extend(der_length(signed.attributes.len()));
    attributes.extend_from_slice(signed.attributes);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, &key)
        .verify(&attributes, signed.signature)
        .map_err(|_| VerifyError::BadSignature)?;

    Ok(signer_info(leaf, ""))
}

fn malformed(what: &str) -> CommitError {
    CommitError::Malformed(what.to_string())
}

/// The commit without its signature, which is what was signed, and the signature's base64.
fn split(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CommitError> {
    const BEGIN: &[u8] = b"gpgsig -----BEGIN SIGNED MESSAGE-----";
    const END: &[u8] = b" -----END SIGNED MESSAGE-----";
    let headers_end = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or_else(|| malformed("the commit has no message"))?;
    let (headers, rest) = raw.split_at(headers_end + 1);
    let mut payload = Vec::with_capacity(raw.len());
    let mut encoded = Vec::new();
    let mut lines = headers.split_inclusive(|b| *b == b'\n').peekable();
    let mut found = false;
    while let Some(line) = lines.next() {
        let bare = line.strip_suffix(b"\n").unwrap_or(line);
        if bare.starts_with(b"gpgsig") {
            if found || bare != BEGIN {
                return Err(malformed("its signature header"));
            }
            found = true;
            let mut ended = false;
            for continued in lines.by_ref() {
                let continued = continued.strip_suffix(b"\n").unwrap_or(continued);
                if continued == END {
                    ended = true;
                    break;
                }
                let body = continued
                    .strip_prefix(b" ")
                    .ok_or_else(|| malformed("its signature's lines"))?;
                encoded.extend_from_slice(body);
            }
            if !ended {
                return Err(malformed("its signature has no end"));
            }
        } else {
            payload.extend_from_slice(line);
        }
    }
    if !found {
        return Err(CommitError::Unsigned);
    }
    payload.extend_from_slice(rest);
    Ok((payload, encoded))
}

/// One thing in BER: its tag, what it holds, and all of it with its header.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    whole: &'a [u8],
}

/// The first thing in `input`, and what follows it. An indefinite length runs to its end-of-contents, found by reading what is inside.
fn read_tlv(input: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8]), CommitError> {
    if depth > MAX_DEPTH {
        return Err(malformed("it is wrapped too deep"));
    }
    let short = || malformed("it is cut short");
    let tag = *input.first().ok_or_else(short)?;
    if tag & 0x1f == 0x1f {
        return Err(malformed("a tag this verifier does not take"));
    }
    let first = *input.get(1).ok_or_else(short)?;
    if first == 0x80 {
        if tag & 0x20 == 0 {
            return Err(malformed(
                "an indefinite length on what holds nothing inside",
            ));
        }
        let start = 2;
        let mut at = start;
        loop {
            let rest = input.get(at..).ok_or_else(short)?;
            if rest.starts_with(&[0, 0]) {
                let value = &input[start..at];
                let whole = &input[..at + 2];
                return Ok((Tlv { tag, value, whole }, &input[at + 2..]));
            }
            let (inner, _) = read_tlv(rest, depth + 1)?;
            at += inner.whole.len();
        }
    }
    let (length, start) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count > 4 {
            return Err(malformed("a length too long to be real"));
        }
        let bytes = input.get(2..2 + count).ok_or_else(short)?;
        (
            bytes.iter().fold(0usize, |n, b| (n << 8) | *b as usize),
            2 + count,
        )
    };
    let end = start.checked_add(length).ok_or_else(short)?;
    let value = input.get(start..end).ok_or_else(short)?;
    let whole = &input[..end];
    Ok((Tlv { tag, value, whole }, &input[end..]))
}

/// The next thing in `input`, which must have this tag.
fn expect<'a>(input: &mut &'a [u8], tag: u8, what: &str) -> Result<Tlv<'a>, CommitError> {
    let (tlv, rest) = read_tlv(input, 0)?;
    if tlv.tag != tag {
        return Err(malformed(what));
    }
    *input = rest;
    Ok(tlv)
}

/// Nothing may be left over: everything in a signature is either checked here or signed.
fn finished(input: &[u8], what: &str) -> Result<(), CommitError> {
    if input.is_empty() {
        Ok(())
    } else {
        Err(malformed(what))
    }
}

/// What a signature says, and the bytes the signature is over.
struct SignedData<'a> {
    certificates: Vec<&'a [u8]>,
    issuer: &'a [u8],
    serial: &'a [u8],
    attributes: &'a [u8],
    message_digest: &'a [u8],
    signature: &'a [u8],
}

/// Reads a `ContentInfo` holding a detached `SignedData` with one signer. Every part that nothing signs (the wrapping, the version, the
/// algorithm lists) is held to the one thing it may be, so that no byte of it can differ.
fn read_signed_data(der: &[u8]) -> Result<SignedData<'_>, CommitError> {
    let mut input = der;
    let info = expect(&mut input, TAG_SEQUENCE, "its outer sequence")?;
    finished(input, "something after the signature")?;

    let mut info = info.value;
    if expect(&mut info, TAG_OID, "its content type")?.value != OID_SIGNED_DATA {
        return Err(malformed("it is not signedData"));
    }
    let wrapper = expect(&mut info, TAG_CONTEXT_0, "its content")?;
    finished(info, "something after its content")?;

    let mut wrapped = wrapper.value;
    let signed = expect(&mut wrapped, TAG_SEQUENCE, "its signedData")?;
    finished(wrapped, "something after its signedData")?;

    let mut signed = signed.value;
    if expect(&mut signed, TAG_INTEGER, "its version")?.value != [1] {
        return Err(malformed("a version this verifier does not take"));
    }
    if expect(&mut signed, TAG_SET, "its digest algorithms")?.value != SHA256 {
        return Err(CommitError::UnsupportedAlgorithm(
            "a digest other than SHA-256".into(),
        ));
    }
    let content = expect(&mut signed, TAG_SEQUENCE, "what it is over")?;
    let mut content = content.value;
    if expect(&mut content, TAG_OID, "what it is over")?.value != OID_DATA {
        return Err(malformed("it is not over data"));
    }
    // Detached: the commit is not inside it.
    finished(content, "a signature that carries its own content")?;

    let certificates = expect(&mut signed, TAG_CONTEXT_0, "its certificates")?;
    let mut bag = certificates.value;
    let mut certs = Vec::new();
    while !bag.is_empty() {
        let cert = expect(&mut bag, TAG_SEQUENCE, "a certificate")?;
        algorithms_agree(cert)?;
        certs.push(cert.whole);
    }

    let signers = expect(&mut signed, TAG_SET, "its signers")?;
    finished(signed, "something after its signers")?;
    let mut signers = signers.value;
    let signer = expect(&mut signers, TAG_SEQUENCE, "its signer")?;
    finished(signers, "more than one signer")?;

    let mut signer = signer.value;
    if expect(&mut signer, TAG_INTEGER, "its signer's version")?.value != [1] {
        return Err(malformed("a signer version this verifier does not take"));
    }
    let id = expect(&mut signer, TAG_SEQUENCE, "who signed")?;
    let mut id = id.value;
    let issuer = expect(&mut id, TAG_SEQUENCE, "the signer's issuer")?.whole;
    let serial = expect(&mut id, TAG_INTEGER, "the signer's serial")?.value;
    finished(id, "more in who signed")?;
    if expect(&mut signer, TAG_SEQUENCE, "its signer's digest")?.whole != SHA256 {
        return Err(CommitError::UnsupportedAlgorithm(
            "a digest other than SHA-256".into(),
        ));
    }
    let attributes = expect(&mut signer, TAG_CONTEXT_0, "what is signed")?;
    let algorithm = expect(&mut signer, TAG_SEQUENCE, "how it is signed")?.whole;
    if algorithm != ECDSA_SHA256 {
        return Err(CommitError::UnsupportedAlgorithm(
            "a signature other than ECDSA on P-256 with SHA-256".into(),
        ));
    }
    let signature = expect(&mut signer, TAG_OCTET_STRING, "the signature")?.value;
    finished(signer, "more after the signature")?;

    Ok(SignedData {
        certificates: certs,
        issuer,
        serial,
        attributes: attributes.value,
        message_digest: signed_digest(attributes.value)?,
        signature,
    })
}

/// What is outside a certificate's signature is held to what it may be, since the X.509 parser takes variations that mean the same: it names
/// its signature algorithm twice, RFC 5280 says the two are the same, and the outer one is held to the signed one, byte for byte.
fn algorithms_agree(certificate: Tlv<'_>) -> Result<(), CommitError> {
    let mut outer = certificate.value;
    let tbs = expect(&mut outer, TAG_SEQUENCE, "a certificate's signed part")?;
    let unsigned = expect(&mut outer, TAG_SEQUENCE, "a certificate's algorithm")?;
    expect(&mut outer, TAG_BIT_STRING, "a certificate's signature")?;
    finished(outer, "more after a certificate's signature")?;
    let mut tbs = tbs.value;
    if tbs.first() == Some(&TAG_CONTEXT_0) {
        expect(&mut tbs, TAG_CONTEXT_0, "a certificate's version")?;
    }
    expect(&mut tbs, TAG_INTEGER, "a certificate's serial")?;
    let signed = expect(&mut tbs, TAG_SEQUENCE, "a certificate's signed algorithm")?;
    if signed.whole != unsigned.whole {
        return Err(malformed("a certificate whose two algorithms differ"));
    }
    Ok(())
}

/// The `messageDigest` among the signed attributes, which must also say the signature is over data.
fn signed_digest(attributes: &[u8]) -> Result<&[u8], CommitError> {
    let mut input = attributes;
    let mut digest = None;
    let mut over_data = false;
    while !input.is_empty() {
        let attribute = expect(&mut input, TAG_SEQUENCE, "an attribute")?;
        let mut attribute = attribute.value;
        let oid = expect(&mut attribute, TAG_OID, "an attribute's name")?.value;
        let values = expect(&mut attribute, TAG_SET, "an attribute's values")?;
        if oid == OID_MESSAGE_DIGEST {
            let mut values = values.value;
            let value = expect(&mut values, TAG_OCTET_STRING, "the digest")?.value;
            finished(values, "more than one digest")?;
            if digest.replace(value).is_some() {
                return Err(malformed("two digests"));
            }
        } else if oid == OID_CONTENT_TYPE {
            let mut values = values.value;
            over_data = expect(&mut values, TAG_OID, "the content type")?.value == OID_DATA;
        }
    }
    if !over_data {
        return Err(malformed(
            "its signed attributes do not say it is over data",
        ));
    }
    digest.ok_or_else(|| malformed("no digest among what is signed"))
}

/// The way up from the signer to a pinned CA, through the certificates the signature carries. A pin is trusted by being pinned, not by what the
/// signature carries.
fn chain_to_a_pin(
    leaf: &X509Certificate<'_>,
    certs: &[X509Certificate<'_>],
    trust: &Trust,
    now: i64,
) -> Result<(), CommitError> {
    valid_at(leaf, now)?;
    let mut at = leaf;
    for _ in 0..MAX_CHAIN {
        if trust.anchors(at, now) {
            return Ok(());
        }
        let Some(issuer) = certs.iter().find(|c| c.subject() == at.issuer()) else {
            return Err(VerifyError::UntrustedRoot.into());
        };
        issued_by(at, issuer, now)?;
        at = issuer;
    }
    Err(VerifyError::ChainTooLong(MAX_CHAIN + 1).into())
}

fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let bytes: Vec<u8> = length
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &[u8] = include_bytes!("../tests/fixtures/deploy-commit.raw");

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_length(value.len()));
        out.extend_from_slice(value);
        out
    }

    fn attribute(oid: &[u8], value: Vec<u8>) -> Vec<u8> {
        tlv(
            TAG_SEQUENCE,
            &[tlv(TAG_OID, oid), tlv(TAG_SET, &value)].concat(),
        )
    }

    fn digest_attribute() -> Vec<u8> {
        attribute(OID_MESSAGE_DIGEST, tlv(TAG_OCTET_STRING, &[7; 32]))
    }

    fn over_data() -> Vec<u8> {
        attribute(OID_CONTENT_TYPE, tlv(TAG_OID, OID_DATA))
    }

    #[test]
    fn the_digest_is_found_among_what_is_signed() {
        let attributes = [over_data(), digest_attribute()].concat();
        assert_eq!(signed_digest(&attributes).unwrap(), [7; 32]);
    }

    #[test]
    fn attributes_that_do_not_say_they_are_over_data_are_refused() {
        assert!(signed_digest(&digest_attribute()).is_err());
        let other = attribute(OID_CONTENT_TYPE, tlv(TAG_OID, OID_SIGNED_DATA));
        assert!(signed_digest(&[other, digest_attribute()].concat()).is_err());
    }

    #[test]
    fn no_digest_or_two_digests_are_refused() {
        assert!(signed_digest(&over_data()).is_err());
        let two = [over_data(), digest_attribute(), digest_attribute()].concat();
        assert!(signed_digest(&two).is_err());
    }

    /// The real signature, with its one signer written twice. The signer's own signature still verifies, so this is only the rule's to catch:
    /// a second signer is something nothing checked.
    #[test]
    fn a_second_signer_is_refused() {
        let (_, encoded) = split(COMMIT).unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert!(read_signed_data(&der).is_ok());

        // The SET of signers is the last thing in the signedData, definite in length inside three indefinite wrappers.
        let set = der
            .windows(4)
            .rposition(|w| w[0] == TAG_SET && matches!(w[1], 0x81 | 0x82))
            .unwrap();
        let (found, after) = read_tlv(&der[set..], 0).unwrap();
        let doubled = tlv(TAG_SET, &[found.value, found.value].concat());
        let spliced = [&der[..set], &doubled, after].concat();
        assert!(matches!(
            read_signed_data(&spliced),
            Err(CommitError::Malformed(why)) if why.contains("more than one signer")
        ));
    }

    #[test]
    fn a_length_or_a_nesting_that_cannot_be_real_is_refused_and_does_not_panic() {
        assert!(read_tlv(&[0x30, 0x85, 1, 1, 1, 1, 1], 0).is_err());
        assert!(read_tlv(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff], 0).is_err());
        assert!(
            read_tlv(&[0x04, 0x80], 0).is_err(),
            "a primitive cannot be indefinite"
        );
        assert!(
            read_tlv(&[0x30, 0x80, 0x30, 0x80, 0, 0], 0).is_err(),
            "no end"
        );
    }

    /// Well formed all the way down, so only the limit stops it: nesting is what would otherwise overflow the stack.
    #[test]
    fn nesting_past_the_limit_is_refused_though_it_is_well_formed() {
        let nested = |levels: usize| -> Vec<u8> {
            let open = std::iter::repeat_n([0x30, 0x80], levels).flatten();
            let close = std::iter::repeat_n([0, 0], levels).flatten();
            open.chain(close).collect()
        };
        assert!(read_tlv(&nested(MAX_DEPTH), 0).is_ok());
        assert!(matches!(
            read_tlv(&nested(MAX_DEPTH + 2), 0),
            Err(CommitError::Malformed(why)) if why.contains("too deep")
        ));
    }
}
