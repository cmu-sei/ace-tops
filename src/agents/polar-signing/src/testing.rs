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

//! Certificates for tests, here and in crates that verify signed documents, minted with rcgen: a CA,
//! optional intermediates, and signers of either key type with the subject and SAN entries cert-issuer
//! puts in a user's certificate. Behind the `testing` feature so nothing ships with it.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SanType, SubjectPublicKeyInfo, date_time_ymd,
};

/// The moment the tests check at.
pub fn now() -> i64 {
    date_time_ymd(2026, 10, 11).unix_timestamp()
}

pub struct Authority {
    pub issuer: Issuer<'static, KeyPair>,
    pub pem: String,
}

pub fn root(name: &str) -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = date_time_ymd(2026, 1, 1);
    params.not_after = date_time_ymd(2100, 1, 1);
    let key = KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    Authority {
        issuer: Issuer::new(params, key),
        pem,
    }
}

pub fn intermediate(parent: &Authority, name: &str, not_after_year: i32) -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = date_time_ymd(2026, 1, 1);
    params.not_after = date_time_ymd(not_after_year, 1, 1);
    let key = KeyPair::generate().unwrap();
    let pem = params.signed_by(&key, &parent.issuer).unwrap().pem();
    Authority {
        issuer: Issuer::new(params, key),
        pem,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    P256,
    Ed25519,
}

pub struct Spec {
    pub kind: Kind,
    pub username: &'static str,
    pub email: &'static str,
    pub identity: &'static str,
    pub capabilities: Vec<&'static str>,
    pub key_usages: Vec<KeyUsagePurpose>,
    pub extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    pub not_before_year: i32,
    pub not_after_year: i32,
    pub is_ca: bool,
}

/// The account ID of the default signer, alice: the first DNS name of her certificate, and the name she is known by in
/// force. An author writes her username, which the credentials agent converts (docs/architecture/authority-model.md,
/// "Decisions").
pub const ALICE_ACCOUNT_ID: &str = "d983a3d2-9b61-41c5-88a0-d123fb50ba33";

impl Default for Spec {
    fn default() -> Self {
        Spec {
            kind: Kind::P256,
            username: "alice",
            email: "alice@example.org",
            identity: ALICE_ACCOUNT_ID,
            capabilities: vec!["c:update-configuration"],
            key_usages: vec![KeyUsagePurpose::DigitalSignature],
            extended_key_usages: vec![ExtendedKeyUsagePurpose::ClientAuth],
            not_before_year: 2026,
            not_after_year: 2030,
            is_ca: false,
        }
    }
}

pub struct Signer {
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn signer(issuer: &Authority, spec: Spec) -> Signer {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(
        DnType::CustomDnType(vec![0, 9, 2342, 19200300, 100, 1, 1]),
        DnValue::Utf8String(spec.username.into()),
    );
    params.distinguished_name.push(
        DnType::CustomDnType(vec![0, 9, 2342, 19200300, 100, 1, 3]),
        DnValue::Ia5String(spec.email.try_into().unwrap()),
    );
    params.subject_alt_names = std::iter::once(SanType::DnsName(spec.identity.try_into().unwrap()))
        .chain(
            spec.capabilities
                .iter()
                .map(|c| SanType::URI((*c).try_into().unwrap())),
        )
        .collect();
    params.key_usages = spec.key_usages;
    params.extended_key_usages = spec.extended_key_usages;
    params.not_before = date_time_ymd(spec.not_before_year, 1, 1);
    params.not_after = date_time_ymd(spec.not_after_year, 1, 1);
    if spec.is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    let key = match spec.kind {
        Kind::P256 => KeyPair::generate().unwrap(),
        Kind::Ed25519 => KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
    };
    let cert_pem = params.signed_by(&key, &issuer.issuer).unwrap().pem();
    Signer {
        cert_pem,
        key_pem: key.serialize_pem(),
    }
}

/// An RSA public key (2048 bits, made once for these tests; its private half was thrown away), which is what an
/// agent's escrow certificate holds.
pub const ESCROW_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmLcTDbxBxdnisvVTSES2\nal7BZH7yBefiUNjdF8rBv7maHUD+9lQXft9aBi98hx+d9hexbdOOM4irqh43kDSF\nxl0kLNTjV5295UbB9fCGsfPY1yQmk4WwT+ZTv4C1yuuGSBssd9ZA7ih2/+oEDT7o\nqn9AeLXRajJkK8y+Dg+5KrQ0uicZ0LhgvRA6VFcfuO0t1ylBzt0UwLM+KCllPmNS\n9jJgZD2/EuewfyqKkqmos99LPxdP1/dOIqN3yZdALd2sE7wM3+ns1/zmFqnUpm6H\nkouqNpfq5Rr22guZyz4ULuxVJ0+KZNGqcz7Lfc8FCR3tGETJfd3a+4dsK35Y55Ic\nRwIDAQAB\n-----END PUBLIC KEY-----\n";

pub struct EscrowSpec {
    /// The DNS name the certificate carries: the agent's normalized identity.
    pub identity: &'static str,
    pub key_usages: Vec<KeyUsagePurpose>,
    pub extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    pub not_before_year: i32,
    pub not_after_year: i32,
    pub is_ca: bool,
}

impl Default for EscrowSpec {
    fn default() -> Self {
        EscrowSpec {
            identity: "git-repo-observer.polar.serviceaccount.cluster.local",
            key_usages: vec![KeyUsagePurpose::KeyEncipherment],
            extended_key_usages: vec![ExtendedKeyUsagePurpose::EmailProtection],
            not_before_year: 2026,
            not_after_year: 2030,
            is_ca: false,
        }
    }
}

/// The credentials agent's authority certificate as cert-issuer makes one (`CertType::Signing`), for `identity`:
/// `digitalSignature` and the one extended key usage `id-kp-documentSigning`. Over any key, by `escrow_certificate_for`.
pub fn authority_spec(identity: &'static str) -> EscrowSpec {
    EscrowSpec {
        identity,
        key_usages: vec![KeyUsagePurpose::DigitalSignature],
        extended_key_usages: vec![ExtendedKeyUsagePurpose::Other(
            cert_issuer_common::OID_DOCUMENT_SIGNING.to_vec(),
        )],
        ..EscrowSpec::default()
    }
}

/// An agent's escrow certificate as cert-issuer makes one (`CertType::Service`): the agent's identity as the DNS
/// name, `keyEncipherment` and the one extended key usage `emailProtection`, over an RSA key, signed by `issuer`.
pub fn escrow_certificate(issuer: &Authority, spec: EscrowSpec) -> String {
    escrow_certificate_for(issuer, spec, ESCROW_PUBLIC_KEY_PEM)
}

/// A P-256 public key, of the kind a custody daemon's escrow key is, with the private half thrown away.
pub fn p256_public_key_pem() -> String {
    rcgen::KeyPair::generate().unwrap().public_key_pem()
}

/// The same, over a public key of the caller's: for a test that has to open what was encrypted to it, or a P-256 key, whose
/// certificate permits `keyAgreement` instead.
pub fn escrow_certificate_for(
    issuer: &Authority,
    spec: EscrowSpec,
    public_key_pem: &str,
) -> String {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::DnsName(spec.identity.try_into().unwrap())];
    params.key_usages = spec.key_usages;
    params.extended_key_usages = spec.extended_key_usages;
    params.not_before = date_time_ymd(spec.not_before_year, 1, 1);
    params.not_after = date_time_ymd(spec.not_after_year, 1, 1);
    if spec.is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    let subject = SubjectPublicKeyInfo::from_pem(public_key_pem).unwrap();
    params.signed_by(&subject, &issuer.issuer).unwrap().pem()
}

/// A `pipeline` certificate with the RSA key `deploy-repo.nu` gives one, and what it needs to sign a commit as `gpgsm` does.
pub struct CommitSigner {
    /// The CA it chains to, to pin.
    pub ca_pem: String,
    certificate: Vec<u8>,
    key: ring::signature::EcdsaKeyPair,
}

/// A signer whose certificate has the common name `name`, under a CA of its own, on P-256 as the deployment PKI's are.
pub fn commit_signer(name: &str) -> CommitSigner {
    let ca = root(&format!("{name}-ca"));
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = date_time_ymd(2026, 1, 1);
    params.not_after = date_time_ymd(2100, 1, 1);
    let certificate = params.signed_by(&key, &ca.issuer).unwrap().der().to_vec();
    CommitSigner {
        ca_pem: ca.pem,
        certificate,
        key: ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &key.serialize_der(),
            &ring::rand::SystemRandom::new(),
        )
        .unwrap(),
    }
}

impl CommitSigner {
    /// `commit`, as `git cat-file commit` gives an unsigned one, with a `gpgsig` header holding a detached CMS signature of it.
    pub fn sign(&self, commit: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if value.len() < 0x80 {
                out.push(value.len() as u8);
            } else {
                let bytes: Vec<u8> = value
                    .len()
                    .to_be_bytes()
                    .into_iter()
                    .skip_while(|b| *b == 0)
                    .collect();
                out.push(0x80 | bytes.len() as u8);
                out.extend(bytes);
            }
            out.extend_from_slice(value);
            out
        }
        const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
        const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
        const CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
        const DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
        const SHA256_ALGORITHM: &[u8] = &[
            0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00,
        ];
        const ECDSA_ALGORITHM: &[u8] = &[
            0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x05, 0x00,
        ];
        let attribute =
            |oid: &[u8], value: Vec<u8>| tlv(0x30, &[tlv(0x06, oid), tlv(0x31, &value)].concat());
        let attributes = [
            attribute(CONTENT_TYPE, tlv(0x06, DATA)),
            attribute(DIGEST, tlv(0x04, &Sha256::digest(commit)[..])),
        ]
        .concat();
        let signature = self
            .key
            .sign(&ring::rand::SystemRandom::new(), &tlv(0x31, &attributes))
            .unwrap();
        let parsed = crate::cert::parse(&self.certificate).unwrap();
        let signer = tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(
                    0x30,
                    &[
                        parsed.issuer().as_raw().to_vec(),
                        tlv(0x02, parsed.tbs_certificate.raw_serial()),
                    ]
                    .concat(),
                ),
                SHA256_ALGORITHM.to_vec(),
                tlv(0xa0, &attributes),
                ECDSA_ALGORITHM.to_vec(),
                tlv(0x04, signature.as_ref()),
            ]
            .concat(),
        );
        let signed = tlv(
            0x30,
            &[
                tlv(0x02, &[1]),
                tlv(0x31, SHA256_ALGORITHM),
                tlv(0x30, &tlv(0x06, DATA)),
                tlv(0xa0, &self.certificate),
                tlv(0x31, &signer),
            ]
            .concat(),
        );
        let info = tlv(0x30, &[tlv(0x06, SIGNED_DATA), tlv(0xa0, &signed)].concat());
        let encoded = base64::engine::general_purpose::STANDARD.encode(info);
        let mut header = b"gpgsig -----BEGIN SIGNED MESSAGE-----\n".to_vec();
        for line in encoded.as_bytes().chunks(64) {
            header.push(b' ');
            header.extend_from_slice(line);
            header.push(b'\n');
        }
        header.extend_from_slice(b" -----END SIGNED MESSAGE-----\n");
        let headers_end = commit.windows(2).position(|w| w == b"\n\n").unwrap() + 1;
        [&commit[..headers_end], &header, &commit[headers_end..]].concat()
    }
}
