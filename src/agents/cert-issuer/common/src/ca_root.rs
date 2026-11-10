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

//! Generating a CA root keypair and its self-signed certificate.
//!
//! Lives in cert-issuer-common, not in the server, so the admin tool's
//! `bootstrap-ca` can generate a CA without depending on the whole
//! server crate. Moved verbatim from cert-issuer/server's ca.rs; the
//! server re-exports it, so existing callers are unchanged.

use rcgen::KeyPair;
use time::OffsetDateTime;

/// Generate a fresh CA root keypair and self-signed certificate.
///
/// Used at bootstrap time (run once per environment) to produce the
/// CA materials the cert issuer will load from disk on subsequent
/// startups. The output is two PEM strings: the CA cert and the CA
/// key.
///
/// Validity defaults to 10 years. CA roots are long-lived; rotation
/// is a separate operational procedure (see module docs).
///
/// It signs only end-entity certificates (path length 0), and its key
/// signs certificates and revocations and nothing else; both extensions
/// are critical. Nothing Polar issues is a CA, so a key the CA issued can
/// never mint a chain of its own. A CA made before 2026-11-10 has
/// neither constraint and keeps working as it is; a new cluster gets them.
///
/// This is intentionally exposed as a library function rather than
/// a separate binary so it can be invoked from a small `cargo run
/// --bin generate-ca` shim or from a test.
pub fn bootstrap_ca(common_name: &str) -> Result<(String, String), String> {
    let mut params: rcgen::CertificateParams = Default::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365 * 10);

    let key_pair = KeyPair::generate().map_err(|e| format!("ca keygen: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("ca self-sign: {e}"))?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    /// The root signs certificates and their revocations and nothing else, and only end-entity certificates: no
    /// certificate it signs can be a CA in turn (path length 0), so a key it issued cannot mint a chain of its own. Both
    /// extensions are critical, so a verifier that cannot read them refuses the chain.
    #[test]
    fn the_root_signs_only_end_entity_certificates_and_their_revocations() {
        let (cert_pem, _key) = bootstrap_ca("Test CA").unwrap();
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();

        let constraints = cert
            .basic_constraints()
            .unwrap()
            .expect("basic constraints");
        assert!(constraints.critical);
        assert!(constraints.value.ca);
        assert_eq!(constraints.value.path_len_constraint, Some(0));

        let usage = cert.key_usage().unwrap().expect("key usage");
        assert!(usage.critical);
        assert!(usage.value.key_cert_sign());
        assert!(usage.value.crl_sign());
        assert!(!usage.value.digital_signature());
        assert!(!usage.value.key_encipherment());

        let lifetime =
            cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp();
        assert!(lifetime <= 365 * 10 * 24 * 3600, "{lifetime}");
    }
}
