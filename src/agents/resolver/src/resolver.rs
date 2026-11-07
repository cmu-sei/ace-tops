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
use oci_client::{Reference, manifest::OciManifest};
use polar::{
    DiscoverySourceRef, ProvenanceEvent,
    cassini::{CassiniClient, TcpClient},
    topics::{KUBERNETES_RESOLUTION_EVENTS, PROVENANCE_EVENTS},
};
use polar_agent_builder::protocol::ProtocolHandle;
use ractor::{Actor, ActorProcessingErr, ActorRef, async_trait};
use std::str::FromStr;
use tracing::{debug, error, info, instrument, warn};

pub struct ResolverAgent;

/// Where an image reference says its image lives ([`ResolverAgent::image_source`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// A registry, by its name as Docker normalizes it (`docker.io` for a pinned name with no host).
    Registry(String),
    /// The node's own image store (registry `localhost`): never fetched, never verified.
    NodeLocal,
    /// A name with no registry host and no digest: never fetched, never verified.
    Unpinned,
}

impl ResolverAgent {
    /// Where an image reference says its image lives, by Docker's rule (`oci_client::Reference` is a port of Docker's
    /// normalize.go): the first component is a registry host when a path follows it and it holds a dot or a colon, or is
    /// `localhost`; a tag's dots are not a host. A name with no host is Docker Hub's ("postgres:17.5" is
    /// docker.io/library/postgres), and it is looked up there only when a digest pins it: the digest proves which image it
    /// is wherever it is fetched from, and a tag on Docker Hub may not be the image a node loaded by that name. A registry
    /// of `localhost` is the node's own image store, as podman names what it builds. `localhost:5000` is a registry like
    /// any other. `None`: not a reference.
    pub fn image_source(uri: &str) -> Option<ImageSource> {
        let reference = Reference::from_str(uri).ok()?;
        let names_a_host = uri.split_once('/').is_some_and(|(first, _)| {
            first.contains('.') || first.contains(':') || first == "localhost"
        });
        Some(if reference.registry() == "localhost" {
            ImageSource::NodeLocal
        } else if !names_a_host && reference.digest().is_none() {
            ImageSource::Unpinned
        } else {
            ImageSource::Registry(reference.registry().to_string())
        })
    }

    #[instrument(level = "debug", name = "resolver.inspect_image", skip(state))]
    async fn inspect_image(
        state: &mut ResolverAgentState,
        image_ref: &str,
    ) -> Result<(OciManifest, String), ActorProcessingErr> {
        debug!("Attempting to resolve image: {image_ref}");
        let reference = Reference::from_str(image_ref)?;
        registry::pull_manifest(&state.protocols, &reference, &state.insecure_registries)
            .await
            .map_err(ActorProcessingErr::from)
    }

    fn forward_event(
        state: &mut ResolverAgentState,
        event: ProvenanceEvent,
    ) -> Result<(), ActorProcessingErr> {
        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(&event)?;

        Ok(state.cassini_client.publish(PublishRequest {
            topic: PROVENANCE_EVENTS.to_string(),
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
                let registry = match Self::image_source(&uri) {
                    Some(ImageSource::Registry(registry)) => registry,
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
                            "not verified: {uri} names no registry and no digest, so nothing says which image it is"
                        );
                        return Ok(());
                    }
                    None => {
                        warn!("not verified: {uri} is not an image reference");
                        return Ok(());
                    }
                };
                match Self::inspect_image(state, &uri).await {
                    Ok((manifest, digest)) => {
                        debug!("Resolved image: \n {manifest:?}");
                        let manifest_data = serde_json::to_vec(&manifest)?;

                        // construct new event, pass source_ref through
                        let event = ProvenanceEvent::OCIArtifactResolved {
                            uri: uri.clone(),
                            digest,
                            manifest_data,
                            registry,
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
    use super::{ImageSource, ResolverAgent};
    use proptest::prelude::*;

    const DIGEST: &str = "sha256:74be7d88879d59479314d30d331733f73cd3ec640fe575a310c9aaa149a4ae6c";

    fn registry(host: &str) -> Option<ImageSource> {
        Some(Registry(host.to_string()))
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
            (&format!("ws-image@{DIGEST}"), registry("docker.io")),
            (&format!("postgres:17.5@{DIGEST}"), registry("docker.io")),
            (&format!("library/postgres@{DIGEST}"), registry("docker.io")),
            // A registry host is the first component when a path follows it (a tag's dots are not a host).
            ("ghcr.io/org/app:1", registry("ghcr.io")),
            ("quay.io/keycloak/keycloak:26.2.4", registry("quay.io")),
            ("docker.io/library/postgres:17.5", registry("docker.io")),
            ("localhost:5000/repo:1", registry("localhost:5000")),
            // `localhost` alone is the node's own image store, pinned or not.
            ("localhost/blitz-portal:latest", Some(NodeLocal)),
            (&format!("localhost/polar-init@{DIGEST}"), Some(NodeLocal)),
            // Not a reference at all.
            ("UPPER/Case:bad tag", None),
        ] {
            assert_eq!(ResolverAgent::image_source(uri), source, "{uri}");
        }
    }

    fn name() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z0-9]{1,6}", 1..3).prop_map(|parts| parts.join("/"))
    }

    fn pin() -> impl Strategy<Value = (Option<String>, Option<String>)> {
        (
            proptest::option::of("[a-z0-9][a-z0-9.]{0,6}"),
            proptest::option::of("[0-9a-f]{64}".prop_map(|hex| format!("sha256:{hex}"))),
        )
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
        /// A name with no registry host is looked up on Docker Hub when, and only when, a digest pins it, since only a
        /// digest proves which image it is wherever it is fetched from.
        #[test]
        fn a_name_with_no_host_is_resolved_only_when_pinned(name in name(), pin in pin()) {
            let source = ResolverAgent::image_source(&written(&name, &pin));
            let expected = if pin.1.is_some() { registry("docker.io") } else { Some(Unpinned) };
            prop_assert_eq!(source, expected);
        }

        /// A name with a registry host is that registry's, and the node's own store is never a registry, pinned or not.
        #[test]
        fn a_name_with_a_host_is_that_hosts(
            host in prop_oneof![
                Just("localhost".to_string()),
                "[a-z]{1,6}\\.[a-z]{2,4}",
                "[a-z]{1,6}:[0-9]{2,5}",
            ],
            name in name(),
            pin in pin(),
        ) {
            let source = ResolverAgent::image_source(&written(&format!("{host}/{name}"), &pin));
            let expected = if host == "localhost" { Some(NodeLocal) } else { registry(&host) };
            prop_assert_eq!(source, expected);
        }
    }
}
