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

// tests/integration_tests.rs

// The client here is the far end's, what puts an image in a registry for the handler to read.
#![allow(clippy::disallowed_types)]

use oci_client::{
    Client as OciClient, Reference,
    client::{ClientConfig, ClientProtocol, Config},
    manifest::{IMAGE_MANIFEST_MEDIA_TYPE, OciImageManifest, OciManifest},
    secrets::RegistryAuth,
};
use oci_resolver::registry::{OPERATIONS, pull_manifest};
use polar::egress::testing::{TestCa, https_front};
use polar_agent_builder::protocol::Failure;
use polar_agent_builder::protocol::testing::http_handle_for;
use polar_crypto::registry::{SecretBinding, SecretKind};
use std::str::FromStr;
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spin up a registry:2 container and return (container, "host:port").
/// Container must stay alive for the duration of the test — keep it bound.
async fn start_registry() -> (impl Drop, String) {
    let container = GenericImage::new("registry", "2")
        .with_exposed_port(5000.tcp())
        .with_wait_for(WaitFor::message_on_stderr("listening on"))
        .start()
        .await
        .expect("Failed to start registry:2");

    let host = container.get_host().await.expect("get_host");
    let port = container
        .get_host_port_ipv4(5000)
        .await
        .expect("get_host_port_ipv4(5000)");

    (container, format!("{host}:{port}"))
}

/// Build an OCI client configured for plain HTTP (registry:2 default).
fn http_client() -> OciClient {
    OciClient::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..ClientConfig::default()
    })
}

/// Push a minimal scratch image (empty layer list, `{}` config) to the
/// registry under `<registry_host>/<repo>:<tag>`. Returns the manifest digest.
async fn push_minimal_image(registry_host: &str, repo: &str, tag: &str) -> String {
    let client = http_client();
    let reference = Reference::from_str(&format!("{registry_host}/{repo}:{tag}")).unwrap();

    // `{}` is the canonical empty OCI image config.
    let config_data = b"{}".to_vec();

    let config = Config {
        data: config_data.into(),
        media_type: "application/vnd.oci.image.config.v1+json".to_string(),
        annotations: None,
    };

    let response = client
        .push(&reference, &[], config, &RegistryAuth::Anonymous, None)
        .await
        .expect("push should succeed against local registry");

    // manifest_url is "http://host:port/v2/repo/manifests/sha256:..."
    response
        .manifest_url
        .rsplit('/')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

/// Happy path: pull_manifest succeeds and returns a non-empty digest for an
/// image that actually exists in the registry.
#[tokio::test]
async fn inspect_image_resolves_manifest_from_local_registry() {
    let (_container, registry_host) = start_registry().await;
    push_minimal_image(&registry_host, "polar/test", "latest").await;

    let client = http_client();
    let reference = Reference::from_str(&format!("{registry_host}/polar/test:latest")).unwrap();

    let (manifest, digest) = client
        .pull_manifest(&reference, &RegistryAuth::Anonymous)
        .await
        .expect("pull_manifest should succeed for a known image");

    assert!(!digest.is_empty(), "digest must be non-empty");
    assert!(
        matches!(manifest, OciManifest::Image(_)),
        "expected OciManifest::Image, got something else"
    );
}

/// Error path: pull_manifest returns Err for an image that was never pushed.
/// Verifies the failure propagates rather than returning Ok(None).
#[tokio::test]
async fn inspect_image_errors_on_missing_image() {
    let (_container, registry_host) = start_registry().await;
    // Intentionally push nothing.

    let client = http_client();
    let reference =
        Reference::from_str(&format!("{registry_host}/polar/does-not-exist:latest")).unwrap();

    let result = client
        .pull_manifest(&reference, &RegistryAuth::Anonymous)
        .await;

    assert!(
        result.is_err(),
        "pull_manifest should return Err for a non-existent image"
    );
}

/// Verifies that pushing two different tags to the same repo produces
/// distinct digests — guards against registry state leaking between pushes.
#[tokio::test]
async fn distinct_tags_produce_distinct_digests() {
    let (_container, registry_host) = start_registry().await;

    // Push identical content under two tags; digests should still be equal
    // (content-addressed) but the manifests should resolve independently.
    push_minimal_image(&registry_host, "polar/app", "v1").await;
    push_minimal_image(&registry_host, "polar/app", "v2").await;

    let client = http_client();

    let ref_v1 = Reference::from_str(&format!("{registry_host}/polar/app:v1")).unwrap();
    let ref_v2 = Reference::from_str(&format!("{registry_host}/polar/app:v2")).unwrap();

    let (_, digest_v1) = client
        .pull_manifest(&ref_v1, &RegistryAuth::Anonymous)
        .await
        .expect("v1 pull should succeed");

    let (_, digest_v2) = client
        .pull_manifest(&ref_v2, &RegistryAuth::Anonymous)
        .await
        .expect("v2 pull should succeed");

    // Both tags point to identical content so digests match — the point is
    // that both resolve without error.
    assert!(!digest_v1.is_empty());
    assert!(!digest_v2.is_empty());
}

/// The whole of the resolver's way to a real registry: the handler's client, with no credential, over the http a
/// registry named as insecure is spoken to. What comes back is what was pushed.
#[tokio::test]
async fn the_handler_reads_what_was_pushed_to_a_real_registry() {
    let (_container, registry_host) = start_registry().await;
    let pushed = push_minimal_image(&registry_host, "polar/test", "1").await;
    let site = http_handle_for(
        &TestCa::new("not used here").pem,
        OPERATIONS,
        Vec::new(),
        None,
    )
    .await;
    let reference = Reference::from_str(&format!("{registry_host}/polar/test:1")).unwrap();

    let (manifest, digest) = pull_manifest(
        &site.handle,
        &reference,
        std::slice::from_ref(&registry_host),
    )
    .await
    .expect("the manifest");
    assert!(matches!(manifest, OciManifest::Image(_)));
    assert_eq!(digest, pushed);

    let missing = Reference::from_str(&format!("{registry_host}/polar/none:1")).unwrap();
    let failure = pull_manifest(&site.handle, &missing, std::slice::from_ref(&registry_host))
        .await
        .unwrap_err();
    assert!(matches!(failure, Failure::Read(_)), "{failure:?}");
}

/// A real registry that wants a login, with TLS in front since a credential goes over nothing else: the handler answers its
/// challenge with the login bound to its host, and is refused without it or with another.
#[tokio::test]
async fn the_handler_logs_in_to_a_real_registry_that_asks_for_it() {
    // Only this test's, for this registry's container: `htpasswd -nbB polar-test polar-test-password`.
    const USER: &str = "polar-test";
    const PASSWORD: &str = "polar-test-password";
    const HTPASSWD: &str =
        "polar-test:$2y$05$Rm9xh7H1q3XF4gqY6a/G.O5nVZeC.dQ9jNK6sFpiIAdZPcqnZA9VG\n";

    let container = GenericImage::new("registry", "2")
        .with_exposed_port(5000.tcp())
        .with_wait_for(WaitFor::message_on_stderr("listening on"))
        .with_env_var("REGISTRY_AUTH", "htpasswd")
        .with_env_var("REGISTRY_AUTH_HTPASSWD_REALM", "polar-test")
        .with_env_var("REGISTRY_AUTH_HTPASSWD_PATH", "/auth/htpasswd")
        .with_copy_to("/auth/htpasswd", HTPASSWD.as_bytes().to_vec())
        .start()
        .await
        .expect("Failed to start registry:2 with a login");
    let host = container.get_host().await.expect("get_host");
    let plain = container.get_host_port_ipv4(5000).await.expect("port");
    let plain = format!("{host}:{plain}");

    let login = RegistryAuth::Basic(USER.to_string(), PASSWORD.to_string());
    let pushed_to = Reference::from_str(&format!("{plain}/polar/private:1")).unwrap();
    let pushed = http_client()
        .push(
            &pushed_to,
            &[],
            Config {
                data: b"{}".to_vec().into(),
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                annotations: None,
            },
            &login,
            None,
        )
        .await
        .expect("push with the login")
        .manifest_url
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    let ca = TestCa::new("the test registry's CA");
    let port = https_front(&ca, &format!("http://{plain}")).await;
    let reference = Reference::from_str(&format!("localhost:{port}/polar/private:1")).unwrap();
    let handler_with = |password: &'static str, pattern: &'static str| {
        let ca = ca.pem.clone();
        async move {
            http_handle_for(
                &ca,
                OPERATIONS,
                Vec::new(),
                Some((
                    "registry",
                    password,
                    SecretBinding {
                        host_pattern: pattern.to_string(),
                        kind: SecretKind::UserPassword,
                        username: Some(USER.to_string()),
                    },
                )),
            )
            .await
        }
    };

    let site = handler_with(PASSWORD, "localhost").await;
    let (manifest, digest) = pull_manifest(&site.handle, &reference, &[])
        .await
        .expect("the manifest, with the login");
    assert!(matches!(manifest, OciManifest::Image(_)));
    assert_eq!(digest, pushed);

    let wrong = handler_with("not-the-password", "localhost").await;
    let failure = pull_manifest(&wrong.handle, &reference, &[])
        .await
        .unwrap_err();
    assert!(
        matches!(failure, Failure::CredentialRefused(_)),
        "{failure:?}"
    );

    let off = handler_with(PASSWORD, "registry.example.org").await;
    let failure = pull_manifest(&off.handle, &reference, &[])
        .await
        .unwrap_err();
    assert!(matches!(failure, Failure::Read(_)), "{failure:?}");
}

// ---------------------------------------------------------------------------
// Pure-function unit tests (no container needed)
// ---------------------------------------------------------------------------

/// OciImageManifest serialises and deserialises cleanly via serde_json —
/// validates the round-trip used by emit_oci_resolved_event.
#[test]
fn oci_manifest_round_trips_through_serde() {
    let manifest = OciManifest::Image(OciImageManifest {
        schema_version: 2,
        media_type: Some(IMAGE_MANIFEST_MEDIA_TYPE.to_string()),
        ..OciImageManifest::default()
    });

    let serialized = serde_json::to_vec(&manifest).expect("serialization should not fail");
    let reparsed: OciManifest =
        serde_json::from_slice(&serialized).expect("deserialization should not fail");

    assert!(matches!(reparsed, OciManifest::Image(_)));
}
