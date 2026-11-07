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

//! The OCI resolver itself: given a discovered image reference, pull its manifest from the
//! registry and publish what was found.

use crate::registry;
use cassini_client::{OfflineBehavior, PublishRequest};
use cassini_types::WireTraceCtx;
use oci_client::Reference;
use polar::{
    DiscoverySourceRef, ProvenanceEvent,
    cassini::{CassiniClient, TcpClient},
    topics::{KUBERNETES_RESOLUTION_EVENTS, PROVENANCE_RESOLUTIONS},
};
use polar_agent_builder::protocol::ProtocolHandle;
use ractor::{Actor, ActorProcessingErr, ActorRef, async_trait};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{debug, error, info, instrument, warn};

pub struct ResolverAgent;

/// Where an image reference says its image lives ([`ResolverAgent::image_source`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// The image to read, from its registry as Docker normalizes it (`docker.io` for a pinned name with no host).
    Registry(Reference),
    /// The node's own image store (registry `localhost`): never fetched, never verified.
    NodeLocal,
    /// Nothing says which image it is: a name with no registry host and no digest, or a container whose kubelet reported
    /// no digest a registry serves and whose spec names none. Never fetched, never verified.
    Unpinned,
}

/// The digest a kubelet's `image_id` says it ran, as a registry serves its manifest: containerd's `repo@sha256:...`, or
/// the same after a legacy runtime's `docker-pullable://`. A bare `sha256:...` is the image's own ID, which no registry
/// serves a manifest by, and is none; so is a digest of an algorithm a registry read does not check.
pub fn kubelet_digest(image_id: &str) -> Option<&str> {
    let (_, digest) = image_id
        .trim_start_matches("docker-pullable://")
        .split_once('@')?;
    let (algorithm, hex) = digest.split_once(':')?;
    let length = match algorithm {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => return None,
    };
    (hex.len() == length && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then_some(digest)
}

/// The most reads the resolver keeps; past it they are all dropped and made again, so a cluster that runs endless
/// images cannot make it hold endless manifests (the broker's decision cache does the same).
pub const MOST_KEPT: usize = 1024;

/// What a read of an image found: its manifest's digest and the manifest as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub digest: String,
    pub manifest_data: Vec<u8>,
}

/// The images read by their digest, kept by where they were read: a digest names one content forever, so a container
/// seen again, or another running the same image, is not read again. Every observation of a pod discovers its images
/// again, and a registry counts the reads (Docker Hub limits them). An image read by a tag is never kept, since a tag
/// can be moved, and neither is a failure.
#[derive(Default)]
pub struct ReadCache {
    entries: HashMap<(String, String, String), Resolved>,
}

impl ReadCache {
    /// Where and by which digest `reference` reads its image, if a digest pins it.
    fn key(reference: &Reference) -> Option<(String, String, String)> {
        let digest = reference.digest()?;
        Some((
            reference.registry().to_string(),
            reference.repository().to_string(),
            digest.to_string(),
        ))
    }

    /// What reading `reference` found before, if a digest pins it and it is still kept.
    pub fn get(&self, reference: &Reference) -> Option<&Resolved> {
        self.entries.get(&Self::key(reference)?)
    }

    /// Keeps what reading `reference` found, if a digest pins it.
    pub fn put(&mut self, reference: &Reference, resolved: Resolved) {
        let Some(key) = Self::key(reference) else {
            return;
        };
        if self.entries.len() >= MOST_KEPT {
            self.entries.clear();
        }
        self.entries.insert(key, resolved);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl ResolverAgent {
    /// Where an image reference says its image lives, by Docker's rule (`oci_client::Reference` is a port of Docker's
    /// normalize.go): the first component is a registry host when a path follows it and it holds a dot or a colon, or is
    /// `localhost`; a tag's dots are not a host. A registry of `localhost` is the node's own image store, as podman names
    /// what it builds; `localhost:5000` is a registry like any other. `None`: not a reference.
    ///
    /// Only a digest proves which image a reference means wherever it is fetched from. A name with no host is Docker
    /// Hub's ("postgres:17.5" is docker.io/library/postgres) and is looked up there only when pinned, since a tag there may
    /// not be the image a node loaded by that name. A pod's container is the image its kubelet ran (`image_id`), read by
    /// that digest from where the spec names and never by a tag, which may have been moved since the pull
    /// (`kubernetes/consume`, "Image discovery: kubelet-attested only").
    pub fn image_source(uri: &str, source_ref: &DiscoverySourceRef) -> Option<ImageSource> {
        let reference = Reference::from_str(uri).ok()?;
        if reference.registry() == "localhost" {
            return Some(ImageSource::NodeLocal);
        }
        let names_a_host = uri.split_once('/').is_some_and(|(first, _)| {
            first.contains('.') || first.contains(':') || first == "localhost"
        });
        Some(match source_ref {
            DiscoverySourceRef::KubernetesPodContainer { image_id, .. } => {
                match image_id.as_deref().and_then(kubelet_digest) {
                    Some(ran) => {
                        ImageSource::Registry(reference.clone_with_digest(ran.to_string()))
                    }
                    None if reference.digest().is_some() => ImageSource::Registry(reference),
                    None => ImageSource::Unpinned,
                }
            }
            DiscoverySourceRef::OCIRepository { .. } => {
                if !names_a_host && reference.digest().is_none() {
                    ImageSource::Unpinned
                } else {
                    ImageSource::Registry(reference)
                }
            }
        })
    }

    /// What reading `reference` finds: kept from an earlier read when a digest pins it, otherwise read from its registry.
    #[instrument(level = "debug", name = "resolver.inspect_image", skip(state))]
    async fn inspect_image(
        state: &mut ResolverAgentState,
        reference: &Reference,
    ) -> Result<Resolved, ActorProcessingErr> {
        if let Some(kept) = state.read.get(reference) {
            debug!("Already read: {reference}");
            return Ok(kept.clone());
        }
        debug!("Attempting to resolve image: {reference}");
        let (manifest, digest) =
            registry::pull_manifest(&state.protocols, reference, &state.insecure_registries)
                .await?;
        debug!("Resolved image: \n {manifest:?}");
        let resolved = Resolved {
            digest,
            manifest_data: serde_json::to_vec(&manifest)?,
        };
        state.read.put(reference, resolved.clone());
        Ok(resolved)
    }

    fn forward_event(
        state: &mut ResolverAgentState,
        event: ProvenanceEvent,
    ) -> Result<(), ActorProcessingErr> {
        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&event)?;

        Ok(state.cassini_client.publish(PublishRequest {
            topic: PROVENANCE_RESOLUTIONS.to_string(),
            payload: payload.into(),
            trace_ctx: WireTraceCtx::from_current_span(),
            offline_behavior: OfflineBehavior::default(),
            share_identity: true,
        })?)
    }
}

pub struct ResolverAgentState {
    pub cassini_client: TcpClient,
    /// What reads a registry: it holds the credentials and goes out as the cluster says.
    pub protocols: ProtocolHandle,
    /// The registries spoken to over plain http.
    pub insecure_registries: Vec<String>,
    /// The images already read by their digest.
    pub read: ReadCache,
}

#[async_trait]
impl Actor for ResolverAgent {
    type Msg = ProvenanceEvent;
    type State = ResolverAgentState;
    type Arguments = ResolverAgentState;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        debug!("{myself:?} starting");
        info!("ready to resolve discovered image references");
        Ok(args)
    }

    async fn handle(
        &self,
        _me: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            ProvenanceEvent::OCIArtifactDiscovered { uri, source_ref } => {
                let reference = match Self::image_source(&uri, &source_ref) {
                    Some(ImageSource::Registry(reference)) => reference,
                    // What no registry can vouch for fails closed: it is never fetched and no event is published, so the
                    // container has no USES_IMAGE edge. Calling an image local or unpinned can only take a verification
                    // away, never give one. The gap is in the graph as a PodContainer with no USES_IMAGE edge (README,
                    // "Images no registry vouches for").
                    Some(ImageSource::NodeLocal) => {
                        info!(
                            "not verified: {uri} is a node-local image (registry localhost), which no registry can vouch for"
                        );
                        return Ok(());
                    }
                    Some(ImageSource::Unpinned) => {
                        info!(
                            "not verified: nothing says which image {uri} is (no digest in it, and none a registry serves from the kubelet)"
                        );
                        return Ok(());
                    }
                    None => {
                        warn!("not verified: {uri} is not an image reference");
                        return Ok(());
                    }
                };
                match Self::inspect_image(state, &reference).await {
                    Ok(Resolved {
                        digest,
                        manifest_data,
                    }) => {
                        // construct new event, pass source_ref through
                        let event = ProvenanceEvent::OCIArtifactResolved {
                            uri: uri.clone(),
                            digest,
                            manifest_data,
                            registry: reference.registry().to_string(),
                            source_ref: source_ref.clone(),
                        };

                        // depending on the source of the discovery, forward to appropriate parties
                        match source_ref {
                            DiscoverySourceRef::KubernetesPodContainer { .. } => {
                                //forward to a k8s consumer

                                let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&event)?;

                                state.cassini_client.publish(PublishRequest {
                                    topic: KUBERNETES_RESOLUTION_EVENTS.to_string(),
                                    payload: payload.into(),
                                    trace_ctx: WireTraceCtx::from_current_span(),
                                    offline_behavior: OfflineBehavior::default(),
                                    share_identity: true,
                                })?;
                            }
                            DiscoverySourceRef::OCIRepository { .. } => (),
                        }

                        Self::forward_event(state, event)?
                    }
                    Err(e) => {
                        error!("Failed to resolve image: {uri}, {e}");
                    }
                }
            }
            _ => warn!("Received unexpected message! {msg:?}"),
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ImageSource::{NodeLocal, Registry, Unpinned};
    use super::{ImageSource, MOST_KEPT, ReadCache, Resolved, ResolverAgent, kubelet_digest};
    use oci_client::Reference;
    use polar::DiscoverySourceRef;
    use proptest::prelude::*;

    const DIGEST: &str = "sha256:74be7d88879d59479314d30d331733f73cd3ec640fe575a310c9aaa149a4ae6c";
    const RAN: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn fetched(whole: &str) -> Option<ImageSource> {
        Some(Registry(whole.parse().expect("a reference")))
    }

    /// Seen hosted in a repository: the reference is all there is.
    fn hosted(uri: &str) -> Option<ImageSource> {
        ResolverAgent::image_source(
            uri,
            &DiscoverySourceRef::OCIRepository {
                repo_uri: uri.to_string(),
            },
        )
    }

    /// Run by a pod's container: the spec's reference and the kubelet's `image_id`.
    fn ran(uri: &str, image_id: Option<&str>) -> Option<ImageSource> {
        ResolverAgent::image_source(
            uri,
            &DiscoverySourceRef::KubernetesPodContainer {
                pod_uid: "pod".to_string(),
                image_id: image_id.map(str::to_string),
                container_name: "app".to_string(),
            },
        )
    }

    #[test]
    fn a_reference_says_where_its_image_lives_by_dockers_rule() {
        for (uri, source) in [
            // A name with no registry host is Docker Hub's, and only its digest says which image it is.
            ("postgres:17.5", Some(Unpinned)),
            ("neo4j:5.26.2", Some(Unpinned)),
            ("ubuntu", Some(Unpinned)),
            ("polar-nu-init:latest", Some(Unpinned)),
            ("library/postgres:17.5", Some(Unpinned)),
            ("ferronserver/ferron:3", Some(Unpinned)),
            (
                &format!("ws-image@{DIGEST}"),
                fetched(&format!("docker.io/library/ws-image@{DIGEST}")),
            ),
            (
                &format!("postgres:17.5@{DIGEST}"),
                fetched(&format!("docker.io/library/postgres:17.5@{DIGEST}")),
            ),
            (
                &format!("library/postgres@{DIGEST}"),
                fetched(&format!("docker.io/library/postgres@{DIGEST}")),
            ),
            // A registry host is the first component when a path follows it (a tag's dots are not a host).
            ("ghcr.io/org/app:1", fetched("ghcr.io/org/app:1")),
            (
                "quay.io/keycloak/keycloak:26.2.4",
                fetched("quay.io/keycloak/keycloak:26.2.4"),
            ),
            (
                "docker.io/library/postgres:17.5",
                fetched("docker.io/library/postgres:17.5"),
            ),
            ("localhost:5000/repo:1", fetched("localhost:5000/repo:1")),
            // `localhost` alone is the node's own image store, pinned or not.
            ("localhost/blitz-portal:latest", Some(NodeLocal)),
            (&format!("localhost/polar-init@{DIGEST}"), Some(NodeLocal)),
            // Not a reference at all.
            ("UPPER/Case:bad tag", None),
        ] {
            assert_eq!(hosted(uri), source, "{uri}");
        }
    }

    #[test]
    fn a_containers_image_is_the_one_the_kubelet_ran() {
        let ran_from = |name: &str| Some(format!("{name}@{RAN}"));
        for (uri, image_id, source) in [
            // The kubelet's digest says which image ran, whatever the tag names now, and pins a name with no host.
            (
                "ghcr.io/org/app:1",
                ran_from("ghcr.io/org/app"),
                fetched(&format!("ghcr.io/org/app@{RAN}")),
            ),
            (
                "neo4j:5.26.2",
                ran_from("docker.io/library/neo4j"),
                fetched(&format!("docker.io/library/neo4j@{RAN}")),
            ),
            (
                "ghcr.io/org/app:1",
                Some(format!("docker-pullable://ghcr.io/org/app@{RAN}")),
                fetched(&format!("ghcr.io/org/app@{RAN}")),
            ),
            (
                &format!("ghcr.io/org/app@{DIGEST}"),
                ran_from("ghcr.io/org/app"),
                fetched(&format!("ghcr.io/org/app@{RAN}")),
            ),
            // With no digest from the kubelet, only the spec's own digest says which image it is.
            (
                &format!("ghcr.io/org/app@{DIGEST}"),
                None,
                fetched(&format!("ghcr.io/org/app@{DIGEST}")),
            ),
            ("ghcr.io/org/app:1", None, Some(Unpinned)),
            // A bare `sha256:...` is the image's own ID, which no registry serves a manifest by.
            ("ghcr.io/org/app:1", Some(RAN.to_string()), Some(Unpinned)),
            ("neo4j:5.26.2", Some(RAN.to_string()), Some(Unpinned)),
            // The node's own store stays unverified, whatever the kubelet ran.
            (
                "localhost/polar-init:latest",
                ran_from("localhost/polar-init"),
                Some(NodeLocal),
            ),
            ("UPPER/Case:bad tag", ran_from("ghcr.io/org/app"), None),
        ] {
            assert_eq!(ran(uri, image_id.as_deref()), source, "{uri} {image_id:?}");
        }
    }

    #[test]
    fn a_kubelets_image_id_gives_the_digest_a_registry_serves() {
        let sha512 = format!("sha512:{}", "ab".repeat(64));
        for (image_id, digest) in [
            (format!("docker.io/library/neo4j@{RAN}"), Some(RAN)),
            (
                format!("docker-pullable://ghcr.io/org/app@{RAN}"),
                Some(RAN),
            ),
            (format!("ghcr.io/org/app@{sha512}"), Some(sha512.as_str())),
            (RAN.to_string(), None),
            (String::new(), None),
            ("ghcr.io/org/app@sha256:abc".to_string(), None),
            (format!("ghcr.io/org/app@md5:{}", "ab".repeat(16)), None),
            (format!("ghcr.io/org/app@{}", RAN.to_uppercase()), None),
            (format!("ghcr.io/org/app@{RAN}/../x"), None),
        ] {
            assert_eq!(kubelet_digest(&image_id), digest, "{image_id}");
        }
    }

    fn resolved(digest: &str) -> Resolved {
        Resolved {
            digest: digest.to_string(),
            manifest_data: digest.as_bytes().to_vec(),
        }
    }

    fn reference(whole: &str) -> Reference {
        whole.parse().expect("a reference")
    }

    /// The `n`th of many images in one repository, each read by its digest, parsed once.
    fn nth(n: usize) -> Reference {
        static MANY: std::sync::OnceLock<Vec<Reference>> = std::sync::OnceLock::new();
        MANY.get_or_init(|| {
            (0..2 * MOST_KEPT)
                .map(|n| reference(&format!("ghcr.io/org/app@sha256:{n:064x}")))
                .collect()
        })[n]
            .clone()
    }

    #[test]
    fn an_image_read_by_its_digest_is_kept_and_one_read_by_a_tag_is_not() {
        let mut cache = ReadCache::default();
        cache.put(&reference("ghcr.io/org/app:1"), resolved(RAN));
        assert!(cache.get(&reference("ghcr.io/org/app:1")).is_none());
        assert!(cache.is_empty());

        cache.put(&reference(&format!("ghcr.io/org/app@{RAN}")), resolved(RAN));
        assert_eq!(
            cache.get(&reference(&format!("ghcr.io/org/app@{RAN}"))),
            Some(&resolved(RAN))
        );
        // A tag beside the digest names the same image.
        assert_eq!(
            cache.get(&reference(&format!("ghcr.io/org/app:1@{RAN}"))),
            Some(&resolved(RAN))
        );
        // The same digest from another repository or registry is another read: where it was read is part of what is said.
        for other in [
            format!("ghcr.io/org/other@{RAN}"),
            format!("quay.io/org/app@{RAN}"),
            format!("ghcr.io/org/app@{DIGEST}"),
        ] {
            assert!(cache.get(&reference(&other)).is_none(), "{other}");
        }
    }

    #[test]
    fn past_the_most_kept_every_read_is_dropped_and_made_again() {
        let mut cache = ReadCache::default();
        for n in 0..MOST_KEPT {
            cache.put(&nth(n), resolved(&n.to_string()));
        }
        assert_eq!(cache.len(), MOST_KEPT);
        cache.put(&nth(MOST_KEPT), resolved("last"));
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&nth(0)).is_none());
        assert_eq!(cache.get(&nth(MOST_KEPT)), Some(&resolved("last")));
    }

    fn name() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z0-9]{1,6}", 1..3).prop_map(|parts| parts.join("/"))
    }

    fn sha256() -> impl Strategy<Value = String> {
        "[0-9a-f]{64}".prop_map(|hex| format!("sha256:{hex}"))
    }

    fn pin() -> impl Strategy<Value = (Option<String>, Option<String>)> {
        (
            proptest::option::of("[a-z0-9][a-z0-9.]{0,6}"),
            proptest::option::of(sha256()),
        )
    }

    fn host() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("localhost".to_string()),
            "[a-z]{1,6}\\.[a-z]{2,4}",
            "[a-z]{1,6}:[0-9]{2,5}",
        ]
    }

    fn written(name: &str, (tag, digest): &(Option<String>, Option<String>)) -> String {
        let tag = tag
            .as_ref()
            .map(|tag| format!(":{tag}"))
            .unwrap_or_default();
        let digest = digest
            .as_ref()
            .map(|digest| format!("@{digest}"))
            .unwrap_or_default();
        format!("{name}{tag}{digest}")
    }

    proptest! {
        /// However many images are read, and in whatever order, no more than the most kept are held, and the last read
        /// is always one of them, with what was read.
        #[test]
        fn the_cache_is_bounded_and_keeps_the_last_read(reads in proptest::collection::vec(0..2 * MOST_KEPT, 0..3 * MOST_KEPT)) {
            let mut cache = ReadCache::default();
            for n in &reads {
                cache.put(&nth(*n), resolved(&n.to_string()));
                prop_assert!(cache.len() <= MOST_KEPT);
                prop_assert_eq!(cache.get(&nth(*n)), Some(&resolved(&n.to_string())));
            }
        }

        /// A name with no registry host is looked up on Docker Hub when, and only when, a digest pins it, since only a
        /// digest proves which image it is wherever it is fetched from.
        #[test]
        fn a_name_with_no_host_is_resolved_only_when_pinned(name in name(), pin in pin()) {
            let uri = written(&name, &pin);
            let expected = match &pin.1 {
                Some(_) => Some(Registry(uri.parse().unwrap())),
                None => Some(Unpinned),
            };
            prop_assert_eq!(hosted(&uri), expected);
        }

        /// A name with a registry host is that registry's, and the node's own store is never a registry, pinned or not.
        #[test]
        fn a_name_with_a_host_is_that_hosts(host in host(), name in name(), pin in pin()) {
            let uri = written(&format!("{host}/{name}"), &pin);
            let source = hosted(&uri);
            if host == "localhost" {
                prop_assert_eq!(source, Some(NodeLocal));
            } else {
                prop_assert_eq!(source, Some(Registry(uri.parse().unwrap())));
            }
        }

        /// What a container is said to use is the image its kubelet ran: read by the kubelet's digest, from where the
        /// spec names, and never by a tag alone.
        #[test]
        fn a_container_is_read_by_the_digest_it_ran(
            host in proptest::option::of(host()),
            name in name(),
            pin in pin(),
            kubelet in proptest::option::of(sha256()),
        ) {
            let named = host.as_ref().map(|host| format!("{host}/{name}")).unwrap_or(name);
            let uri = written(&named, &pin);
            let image_id = kubelet.as_ref().map(|digest| format!("{named}@{digest}"));
            let source = ran(&uri, image_id.as_deref());
            let spec: oci_client::Reference = uri.parse().unwrap();
            match source {
                Some(NodeLocal) => prop_assert_eq!(spec.registry(), "localhost"),
                Some(Unpinned) => {
                    prop_assert_ne!(spec.registry(), "localhost");
                    prop_assert!(kubelet.is_none() && pin.1.is_none());
                }
                Some(Registry(read)) => {
                    prop_assert_ne!(spec.registry(), "localhost");
                    prop_assert_eq!(read.digest(), kubelet.as_deref().or(pin.1.as_deref()));
                    prop_assert_eq!(read.registry(), spec.registry());
                    prop_assert_eq!(read.repository(), spec.repository());
                }
                None => prop_assert!(false, "{} is a reference", uri),
            }
        }
    }
}
