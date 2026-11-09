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

//! What the resolver asks of a registry: an image's manifest, through the HTTP protocol handler, which holds the credential
//! and answers the registry's challenge. What is read here is what came back, with no way to the credential.

use oci_client::Reference;
use oci_client::errors::OciEnvelope;
use oci_client::manifest::{
    IMAGE_MANIFEST_LIST_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE, OciManifest, Versioned,
};
use polar_agent_builder::protocol::http::{Http, Presented, Reply, Request, StatusCode};
use polar_agent_builder::protocol::{
    Credential, Denial, Failure, Location, Operation, OperationDecl, ProtocolHandle, ProtocolKind,
    ReadFailure,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::marker::PhantomData;

/// Reads a manifest with what the signed binding of the registry's host gives.
pub const READ: OperationDecl = OperationDecl {
    name: "registry.manifest.read",
    doc: "reads an image's manifest from its registry with the credential bound to that host",
    protocol: ProtocolKind::HTTP,
    location: Location::Bound {
        credential: Credential::ForHost,
    },
};
/// Reads a manifest from any registry an image names, with no credential: images are not known ahead of time.
pub const READ_ANONYMOUSLY: OperationDecl = OperationDecl {
    name: "registry.manifest.read-anonymously",
    doc: "reads an image's manifest from whatever registry the image names, with no credential",
    protocol: ProtocolKind::HTTP,
    location: Location::Arbitrary,
};
pub const OPERATIONS: &[OperationDecl] = &[READ, READ_ANONYMOUSLY];

/// The media types a manifest may be in, as a registry is asked for them.
const ACCEPTED: [&str; 4] = [
    IMAGE_MANIFEST_MEDIA_TYPE,
    IMAGE_MANIFEST_LIST_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
];

/// Which of the two operations a request is.
pub trait Access: Send + Sync + 'static {
    const DECL: OperationDecl;
}
pub struct WithCredential;
impl Access for WithCredential {
    const DECL: OperationDecl = READ;
}
pub struct Anonymously;
impl Access for Anonymously {
    const DECL: OperationDecl = READ_ANONYMOUSLY;
}

/// Where an image's manifest is. A registry named as insecure is spoken to over http, and any other over https only.
pub fn manifest_url(reference: &Reference, insecure_registries: &[String]) -> String {
    let registry = reference.resolve_registry();
    let scheme = if is_insecure(registry, insecure_registries) {
        "http"
    } else {
        "https"
    };
    format!(
        "{scheme}://{registry}/v2/{repository}/manifests/{wanted}{namespace}",
        repository = reference.repository(),
        wanted = reference
            .digest()
            .unwrap_or_else(|| reference.tag().unwrap_or("latest")),
        namespace = reference
            .namespace()
            .map(|namespace| format!("?ns={namespace}"))
            .unwrap_or_default(),
    )
}

fn is_insecure(registry: &str, insecure_registries: &[String]) -> bool {
    insecure_registries.iter().any(|named| named == registry)
}

/// What a token for this image must allow.
fn scope(reference: &Reference) -> String {
    format!("repository:{}:pull", reference.repository())
}

/// One image's manifest, as `A` reads it.
pub struct ManifestOf<A> {
    url: String,
    scope: String,
    /// The digest the image was named by, which what comes back must have.
    digest: Option<String>,
    access: PhantomData<A>,
}

impl<A> ManifestOf<A> {
    fn new(reference: &Reference, insecure_registries: &[String]) -> Self {
        Self {
            url: manifest_url(reference, insecure_registries),
            scope: scope(reference),
            digest: reference.digest().map(str::to_string),
            access: PhantomData,
        }
    }
}

impl<A: Access> Operation for ManifestOf<A> {
    type Protocol = Http;
    type Output = (OciManifest, String);
    const DECL: OperationDecl = A::DECL;

    fn request(&self) -> Request {
        Request::get_at(self.url.clone())
            .header("accept", ACCEPTED.join(", "))
            .at_a_registry(self.scope.clone())
    }

    fn read(&self, reply: &Reply) -> Result<(OciManifest, String), ReadFailure> {
        read_manifest(reply, self.digest.as_deref())
    }
}

/// The manifest of an image and its digest: with the credential bound to its registry's host if there is one, and with
/// none if nothing is bound there. Any other failure stays one: a credential that was refused does not become an anonymous
/// request. An insecure registry goes with none, since a credential goes over nothing that is not encrypted.
pub async fn pull_manifest(
    protocols: &ProtocolHandle,
    reference: &Reference,
    insecure_registries: &[String],
) -> Result<(OciManifest, String), Failure> {
    if !is_insecure(reference.resolve_registry(), insecure_registries) {
        match protocols
            .ask(ManifestOf::<WithCredential>::new(
                reference,
                insecure_registries,
            ))
            .await
        {
            Err(Failure::Denied(Denial::NoCredentialBound)) => {}
            answered => return answered,
        }
    }
    protocols
        .ask(ManifestOf::<Anonymously>::new(
            reference,
            insecure_registries,
        ))
        .await
}

/// What came back, read: a 200 whose body has the digest it should, in a form the provenance stream takes.
fn read_manifest(
    reply: &Reply,
    reference_digest: Option<&str>,
) -> Result<(OciManifest, String), ReadFailure> {
    if reply.status == StatusCode::UNAUTHORIZED && reply.presented != Presented::Nothing {
        return Err(ReadFailure::CredentialRefused(format!(
            "the registry answered {} to the {} it asked for",
            reply.status,
            reply.presented.as_str()
        )));
    }
    if reply.status != StatusCode::OK {
        let said = serde_json::from_slice::<OciEnvelope>(&reply.body)
            .map(|envelope| format!(": {envelope}"))
            .unwrap_or_default();
        return Err(ReadFailure::Malformed(format!(
            "the registry answered {}{said}",
            reply.status
        )));
    }
    let header =
        match reply.headers.get("docker-content-digest") {
            None => None,
            Some(value) => Some(value.to_str().map_err(|_| {
                ReadFailure::Malformed("its digest header is not text".to_string())
            })?),
        };
    let digest = verified_digest(&reply.body, header, reference_digest)?;
    check_version(&reply.body)?;
    let manifest = serde_json::from_slice(&reply.body)
        .map_err(|e| ReadFailure::Malformed(format!("it is not a manifest: {e}")))?;
    Ok((manifest, digest))
}

/// That it is a manifest of a schema and a media type this understands.
fn check_version(body: &[u8]) -> Result<(), ReadFailure> {
    let versioned: Versioned = serde_json::from_slice(body)
        .map_err(|e| ReadFailure::Malformed(format!("it is not a manifest: {e}")))?;
    if versioned.schema_version != 2 {
        return Err(ReadFailure::Malformed(format!(
            "its schema version is {}, and only 2 is understood",
            versioned.schema_version
        )));
    }
    match versioned.media_type {
        Some(media_type) if !ACCEPTED.contains(&media_type.as_str()) => Err(
            ReadFailure::Malformed(format!("its media type is {media_type}")),
        ),
        _ => Ok(()),
    }
}

/// The digest of `body`, written as `algorithm:hex`, if it is an algorithm a registry uses.
fn digest_as(algorithm: &str, body: &[u8]) -> Option<String> {
    let hex = match algorithm {
        "sha256" => format!("{:x}", Sha256::digest(body)),
        "sha384" => format!("{:x}", Sha384::digest(body)),
        "sha512" => format!("{:x}", Sha512::digest(body)),
        _ => return None,
    };
    Some(format!("{algorithm}:{hex}"))
}

/// That `body` has the digest named, which comes back.
fn check_digest(body: &[u8], named: &str) -> Result<String, ReadFailure> {
    let (algorithm, _) = named
        .split_once(':')
        .ok_or_else(|| ReadFailure::Malformed(format!("`{named}` is not a digest")))?;
    let actual = digest_as(algorithm, body).ok_or_else(|| {
        ReadFailure::Malformed(format!(
            "the digest algorithm `{algorithm}` is not one known"
        ))
    })?;
    if actual != named {
        return Err(ReadFailure::Malformed(format!(
            "its digest is {actual}, and {named} was named"
        )));
    }
    Ok(actual)
}

/// The digest of a manifest. What the image was named by and what the registry's header says must each be the body's, and
/// the header's is the one given: the spec's canonical digest. An empty header is none, and with neither, the body is simply
/// digested.
pub fn verified_digest(
    body: &[u8],
    header: Option<&str>,
    reference_digest: Option<&str>,
) -> Result<String, ReadFailure> {
    if let Some(named) = reference_digest {
        check_digest(body, named)?;
    }
    match header
        .filter(|header| !header.is_empty())
        .or(reference_digest)
    {
        Some(named) => check_digest(body, named),
        None => Ok(format!("sha256:{:x}", Sha256::digest(body))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar::egress::testing::{TestCa, https_front};
    use polar_agent_builder::protocol::testing::{Site, http_handle_for};
    use polar_crypto::registry::{SecretBinding, SecretKind};
    use proptest::prelude::*;
    use std::str::FromStr;
    use std::sync::OnceLock;
    use wiremock::matchers::{header, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const INSECURE: &str = "reg.local:5000";
    const LOGIN: &str = "the-very-secret-password";
    const MANIFEST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aa","size":2},"layers":[]}"#;

    fn ca() -> &'static TestCa {
        static CA: OnceLock<TestCa> = OnceLock::new();
        CA.get_or_init(|| TestCa::new("the test registry's CA"))
    }

    fn reference(image: &str) -> Reference {
        Reference::from_str(image).unwrap()
    }

    fn insecure() -> Vec<String> {
        vec![INSECURE.to_string()]
    }

    fn sha256(body: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(body))
    }

    fn reply(status: StatusCode, body: &[u8], presented: Presented) -> Reply {
        Reply {
            status,
            headers: Default::default(),
            body: body.to_vec(),
            presented,
            credential_looks_base64: false,
        }
    }

    /// A stand-in registry behind TLS, a handler with a login bound to `pattern`, and the port.
    async fn rig(pattern: &str) -> (MockServer, Site, u16) {
        let server = MockServer::start().await;
        let port = https_front(ca(), &server.uri()).await;
        let site = http_handle_for(
            &ca().pem,
            OPERATIONS,
            Vec::new(),
            Some((
                "registry",
                LOGIN,
                SecretBinding {
                    host_pattern: pattern.to_string(),
                    kind: SecretKind::UserPassword,
                    username: Some("me".to_string()),
                    host_key: None,
                },
            )),
        )
        .await;
        (server, site, port)
    }

    /// A registry that answers a Basic login, and otherwise asks for one.
    async fn registry_wanting_a_login(server: &MockServer) {
        let basic = format!("Basic {}", base64_of(format!("me:{LOGIN}").as_bytes()));
        Mock::given(path("/v2/team/app/manifests/1"))
            .and(header("authorization", basic.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string(MANIFEST))
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("www-authenticate", r#"Basic realm="r""#),
            )
            .with_priority(2)
            .mount(server)
            .await;
    }

    fn base64_of(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn registries_named_as_insecure_are_spoken_to_over_http_and_no_other() {
        assert_eq!(
            manifest_url(&reference("reg.local:5000/team/app:1"), &insecure()),
            "http://reg.local:5000/v2/team/app/manifests/1"
        );
        assert_eq!(
            manifest_url(&reference("ghcr.io/team/app:1"), &insecure()),
            "https://ghcr.io/v2/team/app/manifests/1"
        );
        // Named by host and port: another port of the host is another registry.
        assert_eq!(
            manifest_url(&reference("reg.local:5001/team/app:1"), &insecure()),
            "https://reg.local:5001/v2/team/app/manifests/1"
        );
        // And none named means https for every registry.
        assert_eq!(
            manifest_url(&reference("reg.local:5000/team/app:1"), &[]),
            "https://reg.local:5000/v2/team/app/manifests/1"
        );
    }

    #[test]
    fn the_address_is_the_one_a_registry_serves_the_image_at() {
        let digest = sha256(b"x");
        for (image, expected) in [
            (
                "docker.io/library/ubuntu:24.04".to_string(),
                "https://index.docker.io/v2/library/ubuntu/manifests/24.04".to_string(),
            ),
            (
                "ghcr.io/team/app".to_string(),
                "https://ghcr.io/v2/team/app/manifests/latest".to_string(),
            ),
            (
                format!("ghcr.io/team/app:1@{digest}"),
                format!("https://ghcr.io/v2/team/app/manifests/{digest}"),
            ),
        ] {
            assert_eq!(manifest_url(&reference(&image), &[]), expected, "{image}");
        }
    }

    #[test]
    fn a_token_is_asked_for_only_to_read_this_repository() {
        assert_eq!(
            scope(&reference("ghcr.io/team/app:1")),
            "repository:team/app:pull"
        );
    }

    /// The whole of a read with a credential, through the real handler: the registry's host decides which, the login goes
    /// when asked for, and what comes back is the manifest and its digest.
    #[tokio::test]
    async fn a_registry_a_credential_is_bound_to_is_read_with_it() {
        let (server, site, port) = rig("localhost").await;
        registry_wanting_a_login(&server).await;
        let (manifest, digest) = pull_manifest(
            &site.handle,
            &reference(&format!("localhost:{port}/team/app:1")),
            &insecure(),
        )
        .await
        .unwrap();
        assert!(matches!(manifest, OciManifest::Image(_)));
        assert_eq!(digest, sha256(MANIFEST.as_bytes()));
        let records = site.records.lock().unwrap().clone();
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].operation, READ.name);
        assert_eq!(records[0].credential.as_deref(), Some("registry"));
    }

    /// No binding names the host, so it is asked with nothing, and the record says both. This is the old Docker config's
    /// registry with no entry, an empty config and no config at all: nothing is registered for that host.
    #[tokio::test]
    async fn a_registry_no_credential_is_bound_to_is_asked_with_none() {
        let (server, site, port) = rig("registry.example.org").await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MANIFEST))
            .mount(&server)
            .await;
        pull_manifest(
            &site.handle,
            &reference(&format!("localhost:{port}/team/app:1")),
            &insecure(),
        )
        .await
        .unwrap();
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        assert!(!received[0].headers.contains_key("authorization"));
        let records = site.records.lock().unwrap().clone();
        assert_eq!(records.len(), 2, "{records:?}");
        assert_eq!(records[0].operation, READ.name);
        assert_ne!(records[0].verdict, "allowed");
        assert_eq!(records[1].operation, READ_ANONYMOUSLY.name);
        assert!(records[1].arbitrary);
    }

    /// A credential bound to the host of an insecure registry stays home: the old lookup would have sent it in the clear.
    #[tokio::test]
    async fn an_insecure_registry_is_asked_over_http_with_no_credential_even_if_one_is_bound() {
        let (server, site, _) = rig("localhost").await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(MANIFEST))
            .mount(&server)
            .await;
        let registry = server.uri().replace("http://127.0.0.1", "localhost");
        pull_manifest(
            &site.handle,
            &reference(&format!("{registry}/team/app:1")),
            std::slice::from_ref(&registry),
        )
        .await
        .unwrap();
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        assert!(!received[0].headers.contains_key("authorization"));
        let records = site.records.lock().unwrap().clone();
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].operation, READ_ANONYMOUSLY.name);
    }

    /// A credential that fails does not turn into a request with none: what it could read is what is asked for.
    #[tokio::test]
    async fn a_refused_credential_is_a_failure_and_not_an_anonymous_read() {
        let (server, site, port) = rig("localhost").await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("www-authenticate", r#"Basic realm="r""#),
            )
            .mount(&server)
            .await;
        let image = reference(&format!("localhost:{port}/team/app:1"));
        let failure = pull_manifest(&site.handle, &image, &insecure())
            .await
            .unwrap_err();
        assert!(
            matches!(failure, Failure::CredentialRefused(_)),
            "{failure:?}"
        );
        let again = pull_manifest(&site.handle, &image, &insecure())
            .await
            .unwrap_err();
        assert!(matches!(again, Failure::CredentialHeld { .. }), "{again:?}");
        let records = site.records.lock().unwrap().clone();
        assert!(
            records.iter().all(|record| record.operation == READ.name),
            "{records:?}"
        );
    }

    #[test]
    fn what_is_not_a_manifest_is_refused() {
        let ok = StatusCode::OK;
        // What makes each of them wrong is the only thing wrong with it: the rest is the good manifest.
        for (body, why) in [
            ("not json".to_string(), "not a manifest"),
            (r#"{"schemaVersion":2}"#.to_string(), "not a manifest"),
            (
                MANIFEST.replace(r#""schemaVersion":2"#, r#""schemaVersion":1"#),
                "schema version",
            ),
            (
                MANIFEST.replace("application/vnd.oci.image.manifest.v1+json", "text/plain"),
                "media type",
            ),
        ] {
            let Err(ReadFailure::Malformed(said)) =
                read_manifest(&reply(ok, body.as_bytes(), Presented::Nothing), None)
            else {
                panic!("{body} was taken");
            };
            assert!(said.contains(why), "{body}: {said}");
        }
        assert!(read_manifest(&reply(ok, MANIFEST.as_bytes(), Presented::Nothing), None).is_ok());
    }

    #[test]
    fn an_answer_that_is_not_the_manifest_says_what_it_was() {
        let envelope = br#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"no such manifest"}]}"#;
        let Err(ReadFailure::Malformed(why)) = read_manifest(
            &reply(StatusCode::NOT_FOUND, envelope, Presented::Nothing),
            None,
        ) else {
            panic!("a failure");
        };
        assert!(
            why.contains("404") && why.contains("no such manifest"),
            "{why}"
        );
        // A 401 with nothing presented is a registry that wants a credential, and no refusal of one.
        assert!(matches!(
            read_manifest(
                &reply(StatusCode::UNAUTHORIZED, b"", Presented::Nothing),
                None
            ),
            Err(ReadFailure::Malformed(_))
        ));
        assert!(matches!(
            read_manifest(
                &reply(StatusCode::UNAUTHORIZED, b"", Presented::Basic),
                None
            ),
            Err(ReadFailure::CredentialRefused(_))
        ));
        // Being told no for one repository says nothing of the credential: the next may be allowed.
        assert!(matches!(
            read_manifest(&reply(StatusCode::FORBIDDEN, b"", Presented::Basic), None),
            Err(ReadFailure::Malformed(_))
        ));
    }

    #[test]
    fn a_digest_it_cannot_check_is_refused() {
        for named in ["nocolon", "md5:abc", "sha256:0000"] {
            assert!(verified_digest(b"x", Some(named), None).is_err(), "{named}");
            assert!(verified_digest(b"x", None, Some(named)).is_err(), "{named}");
        }
    }

    proptest! {
        /// Whichever digests are named and by whichever algorithm, the body's own are accepted and the header's comes back,
        /// and with none named it is the body's sha256.
        #[test]
        fn a_body_has_its_own_digest(
            body in proptest::collection::vec(any::<u8>(), 0..64),
            header in prop_oneof![Just("sha256"), Just("sha384"), Just("sha512")],
            named in prop_oneof![Just("sha256"), Just("sha384"), Just("sha512")],
        ) {
            let by_header = digest_as(header, &body).unwrap();
            let by_name = digest_as(named, &body).unwrap();
            prop_assert_eq!(verified_digest(&body, Some(&by_header), Some(&by_name)).unwrap(), by_header.clone());
            prop_assert_eq!(verified_digest(&body, Some(&by_header), None).unwrap(), by_header);
            prop_assert_eq!(verified_digest(&body, None, Some(&by_name)).unwrap(), by_name.clone());
            prop_assert_eq!(verified_digest(&body, Some(""), Some(&by_name)).unwrap(), by_name);
            prop_assert_eq!(verified_digest(&body, None, None).unwrap(), sha256(&body));
        }

        /// Another body's digest is refused wherever it is named, so what is published is what the image names.
        #[test]
        fn a_body_with_another_digest_is_refused(
            body in proptest::collection::vec(any::<u8>(), 0..64),
            other in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assume!(body != other);
            let wrong = sha256(&other);
            let right = sha256(&body);
            prop_assert!(verified_digest(&body, Some(&wrong), None).is_err());
            prop_assert!(verified_digest(&body, None, Some(&wrong)).is_err());
            prop_assert!(verified_digest(&body, Some(&wrong), Some(&right)).is_err());
            prop_assert!(verified_digest(&body, Some(&right), Some(&wrong)).is_err());
        }

        /// Only the registries named are ever spoken to in the clear.
        #[test]
        fn a_registry_is_https_unless_it_is_named(
            registry in "[a-z]{1,8}\\.example\\.org(:[0-9]{2,4})?",
            named in proptest::collection::vec("[a-z]{1,8}\\.example\\.org(:[0-9]{2,4})?", 0..4),
        ) {
            let url = manifest_url(&reference(&format!("{registry}/team/app:1")), &named);
            let scheme = if named.contains(&registry) { "http://" } else { "https://" };
            prop_assert!(url.starts_with(scheme), "{}", url);
        }
    }
}
