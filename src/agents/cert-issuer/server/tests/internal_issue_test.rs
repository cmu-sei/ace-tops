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

//! Tests for `Handler::handle_internal_issue` -- the token-free signing
//! path for callers that have already authorized a request elsewhere
//! (credentials-agent, for admin bootstrap and account claims).
//!
//! What's being proven: the caller allowlist is checked before anything
//! else happens, a refused caller never reaches the CA, and an allowed
//! caller gets the same identity-matching guarantee /issue gives against
//! a token -- the CSR's SAN must equal the identity the caller asserts.

use cert_issuer::ca::{
    CaClient, CaError, CaIssueRequest, IssuedCert, RcgenCaClient, load_or_bootstrap_ca,
};
use cert_issuer::handler::{Handler, HandlerBody};
use cert_issuer::oidc::Validator;
use cert_issuer_common::keypair::{KeyAlgorithm, generate_csr};
use cert_issuer_common::{AccountSubject, CertType, InternalIssueRequest, IssueOutcome};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const ALLOWED_CALLER: &str = "credentials-agent.polar.serviceaccount.cluster.local";
const TARGET_IDENTITY: &str = "some-account-uuid.polar.serviceaccount.cluster.local";

/// Panics if ever called -- used by the refusal tests to prove a refused
/// caller never reaches signing at all.
struct PanicCa;

#[async_trait::async_trait]
impl CaClient for PanicCa {
    async fn issue(&self, _req: CaIssueRequest) -> Result<IssuedCert, CaError> {
        panic!("a refused internal-issuance request must never reach the CA");
    }
}

fn real_ca() -> Arc<dyn CaClient> {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("ca.crt");
    let key_path = dir.path().join("ca.key");
    let (cert_pem, key_pem) = load_or_bootstrap_ca(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        "Test CA",
    )
    .expect("bootstrap test CA");
    // RcgenCaClient holds the PEM in memory, so the temp dir can drop.
    Arc::new(RcgenCaClient::new(&cert_pem, &key_pem).expect("construct CA client"))
}

fn handler(ca: Arc<dyn CaClient>, internal_callers: Vec<&str>) -> Handler {
    Handler {
        // Never consulted on this path -- there is no token to validate.
        validator: Arc::new(Validator::new(vec![])),
        ca,
        default_lifetime: Duration::from_secs(3600),
        server_lifetime: Duration::from_secs(43200),
        user_lifetime: Duration::from_secs(43200),
        service_lifetime: Duration::from_secs(31_536_000),
        own_workload: Default::default(),
        instance_asker: None,
        gate: None,
        identity_lifetime_overrides: HashMap::new(),
        internal_callers: internal_callers.into_iter().map(String::from).collect(),
        floor: None,
        ca_cert_pem: String::new(),
    }
}

fn request_for(csr_identity: &str, asserted_identity: &str) -> InternalIssueRequest {
    let csr = generate_csr(csr_identity, &KeyAlgorithm::EcdsaP256, &[]).expect("csr");
    InternalIssueRequest {
        instance_binding: None,
        expires_by: None,
        csr_pem: csr.csr_pem,
        identity: asserted_identity.to_string(),
        cert_type: CertType::Client,
        extra_sans: vec![],
        subject_dn_defaults: None,
        account_subject: None,
    }
}

#[tokio::test]
async fn no_client_certificate_is_refused_before_the_ca() {
    let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(None, request_for(TARGET_IDENTITY, TARGET_IDENTITY))
        .await;

    assert_eq!(response.status, 403);
    match response.body {
        HandlerBody::Error(e) => assert_eq!(e.outcome, IssueOutcome::CallerNotAuthorized),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_peer_not_on_the_allowlist_is_refused_before_the_ca() {
    let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(
            Some("cassini.polar.serviceaccount.cluster.local"),
            request_for(TARGET_IDENTITY, TARGET_IDENTITY),
        )
        .await;

    assert_eq!(response.status, 403);
    match response.body {
        HandlerBody::Error(e) => assert_eq!(e.outcome, IssueOutcome::CallerNotAuthorized),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn an_empty_allowlist_refuses_every_caller() {
    let h = handler(Arc::new(PanicCa), vec![]);
    let response = h
        .handle_internal_issue(
            Some(ALLOWED_CALLER),
            request_for(TARGET_IDENTITY, TARGET_IDENTITY),
        )
        .await;

    assert_eq!(response.status, 403);
    match response.body {
        HandlerBody::Error(e) => assert_eq!(e.outcome, IssueOutcome::CallerNotAuthorized),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn an_allowed_caller_with_a_matching_csr_gets_a_certificate() {
    let h = handler(real_ca(), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(
            Some(ALLOWED_CALLER),
            request_for(TARGET_IDENTITY, TARGET_IDENTITY),
        )
        .await;

    assert_eq!(response.status, 200);
    match response.body {
        HandlerBody::Success(issued) => {
            assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn an_allowed_caller_asserting_a_different_identity_than_the_csr_is_refused() {
    // The caller is trusted to say who the certificate is for, but the
    // CSR must still agree with it -- same guarantee /issue gives
    // against a token-derived identity.
    let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(
            Some(ALLOWED_CALLER),
            request_for(
                "someone-else.polar.serviceaccount.cluster.local",
                TARGET_IDENTITY,
            ),
        )
        .await;

    assert_eq!(response.status, 403);
    match response.body {
        HandlerBody::Error(e) => assert_eq!(e.outcome, IssueOutcome::IdentityMismatch),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn an_empty_asserted_identity_is_rejected() {
    let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(Some(ALLOWED_CALLER), request_for(TARGET_IDENTITY, ""))
        .await;

    assert_eq!(response.status, 400);
    match response.body {
        HandlerBody::Error(e) => assert_eq!(e.outcome, IssueOutcome::InvalidCsr),
        other => panic!("expected an error, got {other:?}"),
    }
}

// ---- an escrow certificate lives as long as service_lifetime says ----

#[tokio::test]
async fn an_escrow_certificate_lives_the_service_lifetime_and_not_the_server_lifetime() {
    // The agent's durable encryption identity (CertType::Service): things are encrypted to it long after the pod
    // that asked has gone, so it is not held to a server certificate's lifetime.
    let h = handler(real_ca(), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(
            Some(ALLOWED_CALLER),
            InternalIssueRequest {
                instance_binding: None,
                expires_by: None,
                cert_type: CertType::Service,
                ..request_for(TARGET_IDENTITY, TARGET_IDENTITY)
            },
        )
        .await;
    assert_eq!(response.status, 200);
    match response.body {
        HandlerBody::Success(issued) => {
            let left = issued.expires_at - time::OffsetDateTime::now_utc();
            assert!(
                left > time::Duration::seconds(31_536_000 - 60)
                    && left <= time::Duration::seconds(31_536_000),
                "the service lifetime, a year here: {left}"
            );
        }
        other => panic!("expected success, got {other:?}"),
    }
}

// ---- a signing certificate: the caller's own, and nobody else's ----

fn signing_request_for(identity: &str) -> InternalIssueRequest {
    InternalIssueRequest {
        instance_binding: None,
        expires_by: None,
        cert_type: CertType::Signing,
        ..request_for(identity, identity)
    }
}

#[tokio::test]
async fn an_internal_caller_is_signed_a_signing_certificate_for_itself_for_the_server_lifetime() {
    let h = handler(real_ca(), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(Some(ALLOWED_CALLER), signing_request_for(ALLOWED_CALLER))
        .await;

    assert_eq!(response.status, 200);
    match response.body {
        HandlerBody::Success(issued) => {
            let left = issued.expires_at - time::OffsetDateTime::now_utc();
            assert!(
                left > time::Duration::seconds(43200 - 60),
                "the server lifetime, not the default: {left}"
            );
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn a_signing_certificate_for_anyone_but_the_caller_is_refused_before_the_ca() {
    let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER, TARGET_IDENTITY]);
    for identity in [
        TARGET_IDENTITY,
        "cassini.polar.serviceaccount.cluster.local",
    ] {
        let response = h
            .handle_internal_issue(Some(ALLOWED_CALLER), signing_request_for(identity))
            .await;
        assert_eq!(response.status, 403, "{identity}");
        match response.body {
            HandlerBody::Error(e) => assert_eq!(e.outcome, IssueOutcome::CallerNotAuthorized),
            other => panic!("expected an error, got {other:?}"),
        }
    }
}

// ---- a checkpoint certificate: the caller's own, naming nothing else, never a pod's ----

const WORKLOAD: &str = "attestation.polar.serviceaccount.cluster.local";
const POD: &str = "pod-uid-1";

fn checkpoint_request_for(identity: &str) -> InternalIssueRequest {
    InternalIssueRequest {
        cert_type: CertType::Checkpoint,
        ..signing_request_for(identity)
    }
}

#[tokio::test]
async fn an_internal_caller_is_signed_a_checkpoint_certificate_for_itself_for_the_server_lifetime()
{
    let h = handler(real_ca(), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(Some(ALLOWED_CALLER), checkpoint_request_for(ALLOWED_CALLER))
        .await;

    assert_eq!(response.status, 200);
    match response.body {
        HandlerBody::Success(issued) => {
            let left = issued.expires_at - time::OffsetDateTime::now_utc();
            assert!(
                left > time::Duration::seconds(43200 - 60),
                "the server lifetime, renewed by the caller: {left}"
            );
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn a_checkpoint_certificate_for_anyone_but_the_caller_or_naming_more_is_refused_before_the_ca()
 {
    let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER, TARGET_IDENTITY]);
    let for_a_pod = InternalIssueRequest {
        instance_binding: Some(POD.to_string()),
        expires_by: Some(time::OffsetDateTime::now_utc().unix_timestamp() + 7200),
        ..checkpoint_request_for(WORKLOAD)
    };
    let naming_more = InternalIssueRequest {
        extra_sans: vec!["c:record-evidence:attestation".to_string()],
        ..checkpoint_request_for(ALLOWED_CALLER)
    };
    for (what, request, status, outcome) in [
        (
            "another identity",
            checkpoint_request_for(TARGET_IDENTITY),
            403,
            IssueOutcome::CallerNotAuthorized,
        ),
        (
            "a pod, on its custodian's behalf",
            for_a_pod,
            403,
            IssueOutcome::CallerNotAuthorized,
        ),
        (
            "another name beside its own",
            naming_more,
            400,
            IssueOutcome::InvalidCsr,
        ),
    ] {
        let response = h.handle_internal_issue(Some(ALLOWED_CALLER), request).await;
        assert_eq!(response.status, status, "{what}");
        match response.body {
            HandlerBody::Error(e) => assert_eq!(e.outcome, outcome, "{what}"),
            other => panic!("expected an error for {what}, got {other:?}"),
        }
    }
}

// ---- a pod's signing key, on its custodian's behalf (docs/architecture/key-custody.md, "Workload signing keys") ----

/// The credentials agent asking, on a custodian's behalf, for `WORKLOAD`'s pod's signing certificate naming `names`.
fn pod_signing_request(names: &[&str]) -> InternalIssueRequest {
    InternalIssueRequest {
        instance_binding: Some(POD.to_string()),
        expires_by: Some(time::OffsetDateTime::now_utc().unix_timestamp() + 7200),
        cert_type: CertType::Signing,
        extra_sans: names.iter().map(|n| n.to_string()).collect(),
        ..request_for(WORKLOAD, WORKLOAD)
    }
}

#[tokio::test]
async fn a_pod_s_signing_certificate_is_signed_for_its_custodian_naming_its_record_types_for_an_hour()
 {
    use cert_issuer_common::evidence::{MayRecord, may_record};
    let h = handler(real_ca(), vec![ALLOWED_CALLER]);
    for names in [
        vec!["c:record-evidence:attestation"],
        // a multi-instance workload's pod, named as its client certificate names it
        vec![
            "c:record-evidence:attestation",
            "c:record-evidence:attestation-report",
            "i:uid:pod-uid-1",
            "i:pod:attestation-7f9c-x2",
        ],
    ] {
        let response = h
            .handle_internal_issue(Some(ALLOWED_CALLER), pod_signing_request(&names))
            .await;
        assert_eq!(response.status, 200, "{names:?}");
        let HandlerBody::Success(issued) = response.body else {
            panic!("expected success for {names:?}")
        };
        let left = issued.expires_at - time::OffsetDateTime::now_utc();
        assert!(
            left <= time::Duration::seconds(3600),
            "the default lifetime, a pod's, not the server lifetime: {left}"
        );
        let types = names
            .iter()
            .filter_map(|n| n.strip_prefix("c:record-evidence:"))
            .map(str::to_string)
            .collect();
        assert_eq!(
            may_record(&issued.certificate_pem).unwrap(),
            MayRecord::Only(types)
        );
        let names_in_it = uri_names(&issued.certificate_pem);
        for name in &names {
            assert!(names_in_it.contains(&name.to_string()), "{name}");
        }
    }
}

#[tokio::test]
async fn a_signing_certificate_for_another_is_refused_unless_for_a_pod_naming_only_its_record_types()
 {
    let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER]);
    let without_pod = InternalIssueRequest {
        instance_binding: None,
        ..pod_signing_request(&["c:record-evidence:attestation"])
    };
    let without_end = InternalIssueRequest {
        expires_by: None,
        ..pod_signing_request(&["c:record-evidence:attestation"])
    };
    let mut cases = vec![("no pod", without_pod), ("no end", without_end)];
    for (why, names) in [
        ("no record type", vec![]),
        ("any record type", vec!["c:record-evidence"]),
        (
            "any record type beside one",
            vec!["c:record-evidence", "c:record-evidence:attestation"],
        ),
        (
            "a malformed record type",
            vec!["c:record-evidence:Attestation"],
        ),
        (
            "a topic",
            vec!["c:record-evidence:attestation", "p:pub:polar.attestation"],
        ),
        (
            "a group",
            vec!["c:record-evidence:attestation", "g:encryption"],
        ),
        (
            "another capability",
            vec!["c:record-evidence:attestation", "c:revoke"],
        ),
        (
            "a custody name",
            vec!["c:record-evidence:attestation", "p:custody:client"],
        ),
        (
            "another pod",
            vec!["c:record-evidence:attestation", "i:uid:pod-uid-2"],
        ),
    ] {
        cases.push((why, pod_signing_request(&names)));
    }
    for (why, request) in cases {
        let response = h.handle_internal_issue(Some(ALLOWED_CALLER), request).await;
        assert_ne!(response.status, 200, "{why}");
        assert!(
            matches!(&response.body, HandlerBody::Error(e)
                if matches!(e.outcome, IssueOutcome::CallerNotAuthorized | IssueOutcome::InvalidCsr)),
            "{why}: {:?}",
            response.body
        );
    }
}

mod pod_signing_props {
    use super::*;
    use proptest::prelude::*;

    const SCOPED: [&str; 2] = [
        "c:record-evidence:attestation",
        "c:record-evidence:attestation-report",
    ];

    fn a_name() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            SCOPED[0],
            SCOPED[1],
            "c:record-evidence",
            "c:record-evidence:Bad",
            "c:record-evidence:",
            "c:grant",
            "p:pub:polar.attestation",
            "p:sub:polar.attestation",
            "g:encryption",
            "p:custody:signing",
        ])
    }

    proptest! {
        // The rule, for every set of names asked for: a pod's signing certificate is signed exactly when it names at
        // least one record type and nothing but record types, and then it may record those types and no others.
        #[test]
        fn a_pod_s_signing_certificate_is_signed_exactly_when_it_names_record_types_alone(
            names in prop::collection::vec(a_name(), 0..5)
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let h = handler(real_ca(), vec![ALLOWED_CALLER]);
            let response = runtime.block_on(
                h.handle_internal_issue(Some(ALLOWED_CALLER), pod_signing_request(&names)),
            );
            let lawful = !names.is_empty() && names.iter().all(|n| SCOPED.contains(n));
            prop_assert_eq!(response.status == 200, lawful, "{:?}", names);
            if let HandlerBody::Success(issued) = response.body {
                prop_assert_eq!(
                    cert_issuer_common::evidence::may_record(&issued.certificate_pem).unwrap(),
                    cert_issuer_common::evidence::MayRecord::of_names(names.iter().copied())
                );
            }
        }
    }
}

// ---- authoritative account subject (uid, mail) ----

const OID_UID: &str = "0.9.2342.19200300.100.1.1";
const OID_MAIL: &str = "0.9.2342.19200300.100.1.3";

fn request_with_subject(username: &str, email: &str) -> InternalIssueRequest {
    let mut request = request_for(TARGET_IDENTITY, TARGET_IDENTITY);
    request.account_subject = Some(AccountSubject {
        username: username.to_string(),
        email: email.to_string(),
    });
    request
}

fn certificate_of(body: HandlerBody) -> String {
    match body {
        HandlerBody::Success(issued) => issued.certificate_pem,
        other => panic!("expected success, got {other:?}"),
    }
}

/// The value of one Subject DN attribute in the (leaf) certificate.
fn subject_attribute(certificate_pem: &str, oid: &str) -> Option<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
    for rdn in cert.subject().iter() {
        for atv in rdn.iter() {
            if atv.attr_type().to_id_string() == oid {
                return atv.as_str().ok().map(String::from);
            }
        }
    }
    None
}

#[tokio::test]
async fn an_account_subject_becomes_uid_and_mail_in_the_certificate() {
    let h = handler(real_ca(), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(
            Some(ALLOWED_CALLER),
            request_with_subject("alice", "alice@example.com"),
        )
        .await;

    assert_eq!(response.status, 200);
    let pem = certificate_of(response.body);
    assert_eq!(subject_attribute(&pem, OID_UID).as_deref(), Some("alice"));
    assert_eq!(
        subject_attribute(&pem, OID_MAIL).as_deref(),
        Some("alice@example.com")
    );
}

#[tokio::test]
async fn without_an_account_subject_the_certificate_has_no_uid_or_mail() {
    let h = handler(real_ca(), vec![ALLOWED_CALLER]);
    let response = h
        .handle_internal_issue(
            Some(ALLOWED_CALLER),
            request_for(TARGET_IDENTITY, TARGET_IDENTITY),
        )
        .await;

    assert_eq!(response.status, 200);
    let pem = certificate_of(response.body);
    assert_eq!(subject_attribute(&pem, OID_UID), None);
    assert_eq!(subject_attribute(&pem, OID_MAIL), None);
}

#[tokio::test]
async fn a_csr_cannot_claim_its_own_uid_or_mail() {
    // A CSR that puts uid and mail in its own subject is the user speaking
    // for themselves about fields that are admin-authoritative. Both are
    // ignored: with an account subject the caller's values win, and
    // without one the certificate carries neither.
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![TARGET_IDENTITY.to_string()]).unwrap();
    params.distinguished_name.push(
        rcgen::DnType::CustomDnType(vec![0, 9, 2342, 19200300, 100, 1, 1]),
        "attacker",
    );
    params.distinguished_name.push(
        rcgen::DnType::CustomDnType(vec![0, 9, 2342, 19200300, 100, 1, 3]),
        "attacker@evil.example",
    );
    let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

    let h = handler(real_ca(), vec![ALLOWED_CALLER]);

    let mut with_subject = request_with_subject("alice", "alice@example.com");
    with_subject.csr_pem = csr_pem.clone();
    let response = h
        .handle_internal_issue(Some(ALLOWED_CALLER), with_subject)
        .await;
    assert_eq!(response.status, 200);
    let pem = certificate_of(response.body);
    assert_eq!(subject_attribute(&pem, OID_UID).as_deref(), Some("alice"));
    assert_eq!(
        subject_attribute(&pem, OID_MAIL).as_deref(),
        Some("alice@example.com")
    );

    let mut without_subject = request_for(TARGET_IDENTITY, TARGET_IDENTITY);
    without_subject.csr_pem = csr_pem;
    let response = h
        .handle_internal_issue(Some(ALLOWED_CALLER), without_subject)
        .await;
    assert_eq!(response.status, 200);
    let pem = certificate_of(response.body);
    assert_eq!(subject_attribute(&pem, OID_UID), None);
    assert_eq!(subject_attribute(&pem, OID_MAIL), None);
}

#[tokio::test]
async fn a_malformed_account_subject_is_an_internal_error_and_never_reaches_the_ca() {
    for (username, email) in [
        ("alice", "not-an-email"),
        ("alice", "a@b@c"),
        ("alice", "al ice@example.com"),
        ("", "alice@example.com"),
        ("ali\nce", "alice@example.com"),
    ] {
        let h = handler(Arc::new(PanicCa), vec![ALLOWED_CALLER]);
        let response = h
            .handle_internal_issue(Some(ALLOWED_CALLER), request_with_subject(username, email))
            .await;

        assert_eq!(response.status, 500, "{username:?} / {email:?}");
        match response.body {
            HandlerBody::Error(e) => assert_eq!(e.outcome, IssueOutcome::InternalError),
            other => panic!("expected an error, got {other:?}"),
        }
    }
}

/// The URI names of a certificate.
fn uri_names(certificate_pem: &str) -> Vec<String> {
    use x509_parser::prelude::*;
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
    cert.subject_alternative_name()
        .unwrap()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::URI(u) => Some(u.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn a_server_the_credentials_agent_vouches_for_carries_its_floor_entry_s_groups() {
    // docs/architecture/configurations-under-test.md, CT2: the test GitLab's server certificate, as polar-init asks the credentials
    // agent for it, carries `g:under-test` from its floor entry, which the credentials agent has no word on.
    let identity = "gitlab.gitlab-test.serviceaccount.cluster.local";
    let name = "gitlab.gitlab-test.svc.cluster.local";
    let mut h = handler(real_ca(), vec![ALLOWED_CALLER]);
    h.floor = Some(vec![cert_issuer::floor::BootstrapIdentity {
        workload: "system:serviceaccount:gitlab-test:gitlab".to_string(),
        cert_type: CertType::Server,
        names: vec![name.to_string()],
        vouched_only: true,
        publish: vec![],
        subscribe: vec![],
        groups: vec!["under-test".to_string()],
    }]);
    let mut request = request_for(identity, identity);
    request.cert_type = CertType::Server;
    request.extra_sans = vec![name.to_string()];
    let response = h.handle_internal_issue(Some(ALLOWED_CALLER), request).await;
    assert_eq!(response.status, 200, "{:?}", response.body);
    assert_eq!(
        uri_names(&certificate_of(response.body)),
        vec!["g:under-test".to_string()]
    );
}
