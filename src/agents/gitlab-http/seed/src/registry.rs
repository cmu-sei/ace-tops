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

//! A project's container registry, as much as pushing one image takes: a token from GitLab for the repository, each blob it does
//! not have, and the manifest under each tag. Pushing again changes nothing: the digests are the same.

use crate::oci::{Image, MANIFEST_TYPE};
use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use std::net::SocketAddr;
use url::Url;

pub struct Registry {
    http: reqwest::Client,
    registry: Url,
    gitlab: Url,
    token: String,
}

/// `url` with its host reached at `connect` (a port-forward), the name kept for the certificate.
fn reached(
    builder: reqwest::ClientBuilder,
    url: &mut Url,
    connect: Option<SocketAddr>,
) -> Result<reqwest::ClientBuilder> {
    let Some(addr) = connect else {
        return Ok(builder);
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("{url} has no host"))?
        .to_string();
    url.set_port(Some(addr.port()))
        .map_err(|_| anyhow!("{url} cannot take a port"))?;
    Ok(builder.resolve(&host, addr))
}

impl Registry {
    /// `registry` is the registry's address, `gitlab` GitLab's, which issues its tokens; each reached at its own `connect` if given.
    pub fn new(
        registry: Url,
        gitlab: Url,
        token: String,
        ca: Option<&[u8]>,
        connect_registry: Option<SocketAddr>,
        connect_gitlab: Option<SocketAddr>,
    ) -> Result<Self> {
        let mut builder = reqwest::Client::builder();
        if let Some(pem) = ca {
            let certificate =
                reqwest::Certificate::from_pem(pem).context("the CA is not a PEM certificate")?;
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(certificate);
        }
        // Both names may be one host on two ports: a host is resolved to one address, and each URL keeps its own port.
        let (mut registry, mut gitlab) = (registry, gitlab);
        builder = reached(builder, &mut registry, connect_registry)?;
        builder = reached(builder, &mut gitlab, connect_gitlab)?;
        Ok(Registry {
            http: builder.build()?,
            registry,
            gitlab,
            token,
        })
    }

    /// A token to push and pull `repository`, from GitLab, as root with root's personal access token.
    async fn bearer(&self, repository: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Token {
            token: String,
        }
        let mut url = self.gitlab.join("/jwt/auth")?;
        url.query_pairs_mut()
            .append_pair("service", "container_registry")
            .append_pair("scope", &format!("repository:{repository}:push,pull"));
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("root:{}", self.token));
        let response = self
            .http
            .get(url)
            .header("authorization", format!("Basic {basic}"))
            .send()
            .await
            .map_err(|e| anyhow!("a registry token: {}", e.without_url()))?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "a registry token for {repository}: {}",
                response.status()
            ));
        }
        Ok(response
            .json::<Token>()
            .await
            .context("a registry token: an answer of another shape")?
            .token)
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        bearer: &str,
        body: Option<(Vec<u8>, &str)>,
    ) -> Result<reqwest::Response> {
        let what = format!("{method} {}", url.path());
        let mut request = self
            .http
            .request(method, url)
            .header("authorization", format!("Bearer {bearer}"));
        if let Some((bytes, content_type)) = body {
            request = request.header("content-type", content_type).body(bytes);
        }
        request
            .send()
            .await
            .map_err(|e| anyhow!("{what}: {}", e.without_url()))
    }

    async fn blob(&self, repository: &str, bearer: &str, digest: &str, bytes: &[u8]) -> Result<()> {
        let at = self
            .registry
            .join(&format!("/v2/{repository}/blobs/{digest}"))?;
        if self.send(Method::HEAD, at, bearer, None).await?.status() == StatusCode::OK {
            return Ok(());
        }
        let started = self
            .send(
                Method::POST,
                self.registry
                    .join(&format!("/v2/{repository}/blobs/uploads/"))?,
                bearer,
                None,
            )
            .await?;
        if started.status() != StatusCode::ACCEPTED {
            return Err(anyhow!(
                "starting an upload to {repository}: {}",
                started.status()
            ));
        }
        let location = started
            .headers()
            .get("location")
            .and_then(|l| l.to_str().ok())
            .ok_or_else(|| anyhow!("an upload to {repository} with no Location"))?;
        let mut put = self.registry.join(location)?;
        put.query_pairs_mut().append_pair("digest", digest);
        let done = self
            .send(
                Method::PUT,
                put,
                bearer,
                Some((bytes.to_vec(), "application/octet-stream")),
            )
            .await?;
        if !done.status().is_success() {
            return Err(anyhow!(
                "uploading {digest} to {repository}: {}",
                done.status()
            ));
        }
        Ok(())
    }

    /// `image` in `repository`, under each of `tags`.
    pub async fn push(&self, repository: &str, image: &Image, tags: &[String]) -> Result<()> {
        let bearer = self.bearer(repository).await?;
        self.blob(repository, &bearer, &image.config_digest, &image.config)
            .await?;
        self.blob(repository, &bearer, &image.layer_digest, &image.layer)
            .await?;
        for tag in tags {
            let at = self
                .registry
                .join(&format!("/v2/{repository}/manifests/{tag}"))?;
            let put = self
                .send(
                    Method::PUT,
                    at,
                    &bearer,
                    Some((image.manifest.clone(), MANIFEST_TYPE)),
                )
                .await?;
            if !put.status().is_success() {
                return Err(anyhow!(
                    "the manifest for {repository}:{tag}: {}",
                    put.status()
                ));
            }
        }
        Ok(())
    }
}
