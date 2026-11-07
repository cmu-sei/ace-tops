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

//! GitLab's REST API, as much as the seed needs: each `ensure_` finds a thing by its name and makes it only if it is not there, so the
//! seed is safe to run again. The token is sent as `PRIVATE-TOKEN` and is never in an error.

use crate::dataset::{Group, Package, Project, User};
use anyhow::{Context, Result, anyhow};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::net::SocketAddr;
use url::Url;

/// How long a read waits for a GitLab that is warming up: a try every `WARMING_WAIT`, `WARMING_TRIES` times.
const WARMING_TRIES: u32 = 60;
const WARMING_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

pub struct Gitlab {
    http: reqwest::Client,
    base: Url,
    token: String,
}

#[derive(Debug, Deserialize)]
struct Id {
    id: u64,
}

/// A pipeline as the API lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct Pipeline {
    pub id: u64,
    pub status: String,
}

/// A pipeline's status that will not change.
pub fn finished(status: &str) -> bool {
    matches!(status, "success" | "failed" | "canceled" | "skipped")
}

fn segment(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

impl Gitlab {
    /// `base` is GitLab's own address; `ca`, a PEM the server's certificate chains to, in place of the system's roots; `connect`, where
    /// to reach it (a port-forward), the name in `base` still the one its certificate is checked against.
    pub fn new(
        base: Url,
        token: String,
        ca: Option<&[u8]>,
        connect: Option<SocketAddr>,
    ) -> Result<Self> {
        let mut builder = reqwest::Client::builder();
        if let Some(pem) = ca {
            let certificate =
                reqwest::Certificate::from_pem(pem).context("the CA is not a PEM certificate")?;
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(certificate);
        }
        let mut base = base;
        if let Some(addr) = connect {
            let host = base
                .host_str()
                .ok_or_else(|| anyhow!("{base} has no host"))?
                .to_string();
            base.set_port(Some(addr.port()))
                .map_err(|_| anyhow!("{base} cannot take a port"))?;
            builder = builder.resolve(&host, addr);
        }
        Ok(Gitlab {
            http: builder.build()?,
            base,
            token,
        })
    }

    /// A request, and for a read, asked again while GitLab answers that its gateway has no backend yet (502, 503, 504): a GitLab
    /// just started does while Puma comes up. A write is asked once; a seed run again repairs what one left.
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        let mut tries = 0;
        loop {
            let answer = self.call_once(method.clone(), path, body).await?;
            let warming = matches!(
                answer.0,
                StatusCode::BAD_GATEWAY
                    | StatusCode::SERVICE_UNAVAILABLE
                    | StatusCode::GATEWAY_TIMEOUT
            );
            if method != Method::GET || !warming || tries >= WARMING_TRIES {
                return Ok(answer);
            }
            tries += 1;
            tokio::time::sleep(WARMING_WAIT).await;
        }
    }

    async fn call_once(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        let url = self
            .base
            .join(path)
            .with_context(|| format!("{path} is not a path"))?;
        let mut request = self
            .http
            .request(method.clone(), url)
            .header("PRIVATE-TOKEN", &self.token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| anyhow!("{method} {path}: {}", e.without_url()))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// The answer to a GET, or None when GitLab has no such thing.
    async fn find<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        match self.call(Method::GET, path, None).await? {
            (StatusCode::NOT_FOUND, _) => Ok(None),
            (s, body) if s.is_success() => {
                Ok(Some(serde_json::from_value(body).with_context(|| {
                    format!("GET {path}: an answer of another shape")
                })?))
            }
            (s, _) => Err(anyhow!("GET {path}: {s}")),
        }
    }

    async fn make<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        match self.call(Method::POST, path, Some(&body)).await? {
            (s, answer) if s.is_success() => serde_json::from_value(answer)
                .with_context(|| format!("POST {path}: an answer of another shape")),
            (s, answer) => Err(anyhow!(
                "POST {path}: {s}: {}",
                answer.get("message").cloned().unwrap_or(Value::Null)
            )),
        }
    }

    /// A user, with a random password no one is told: the seed's users never sign in.
    pub async fn ensure_user(&self, u: &User) -> Result<u64> {
        let found: Vec<Id> = self
            .find(&format!("/api/v4/users?username={}", segment(&u.username)))
            .await?
            .unwrap_or_default();
        if let Some(user) = found.first() {
            return Ok(user.id);
        }
        let made: Id = self
            .make(
                "/api/v4/users",
                json!({
                    "username": u.username, "name": u.name, "email": u.email,
                    "force_random_password": true, "skip_confirmation": true,
                }),
            )
            .await?;
        Ok(made.id)
    }

    /// A group by its full path, made under `parent` (its id) if it is not there.
    pub async fn ensure_group(&self, g: &Group, parent: Option<u64>) -> Result<u64> {
        if let Some(found) = self
            .find::<Id>(&format!("/api/v4/groups/{}", segment(&g.full_path)))
            .await?
        {
            return Ok(found.id);
        }
        let mut body = json!({ "name": g.path, "path": g.path, "visibility": "private" });
        if let Some(parent) = parent {
            body["parent_id"] = json!(parent);
        }
        Ok(self.make::<Id>("/api/v4/groups", body).await?.id)
    }

    pub async fn ensure_member(&self, group: u64, user: u64, access_level: u8) -> Result<()> {
        if self
            .find::<Id>(&format!("/api/v4/groups/{group}/members/{user}"))
            .await?
            .is_none()
        {
            self.make::<Value>(
                &format!("/api/v4/groups/{group}/members"),
                json!({ "user_id": user, "access_level": access_level }),
            )
            .await?;
        }
        Ok(())
    }

    /// A project by its full path, made in its group (`namespace`, an id) with a `main` branch if it is not there.
    pub async fn ensure_project(&self, p: &Project, namespace: u64) -> Result<u64> {
        if let Some(found) = self
            .find::<Id>(&format!("/api/v4/projects/{}", segment(&p.full_path)))
            .await?
        {
            return Ok(found.id);
        }
        let made: Id = self
            .make("/api/v4/projects", json!({
                "name": p.path, "path": p.path, "namespace_id": namespace, "visibility": "private",
                "initialize_with_readme": p.readme, "default_branch": "main",
            }))
            .await?;
        Ok(made.id)
    }

    /// A file on `main`, committed only if it is not there: true when it was.
    pub async fn ensure_file(
        &self,
        project: u64,
        path: &str,
        content: &str,
        message: &str,
    ) -> Result<bool> {
        let at = format!(
            "/api/v4/projects/{project}/repository/files/{}",
            segment(path)
        );
        if self
            .find::<Value>(&format!("{at}?ref=main"))
            .await?
            .is_some()
        {
            return Ok(false);
        }
        self.make::<Value>(
            &at,
            json!({ "branch": "main", "content": content, "commit_message": message }),
        )
        .await?;
        Ok(true)
    }

    /// A GraphQL request POSTed to GitLab's endpoint, and the `data` of its answer; an answer with errors is an error.
    pub async fn graphql(&self, body: Value) -> Result<Value> {
        match self.call(Method::POST, "/api/graphql", Some(&body)).await? {
            (s, answer)
                if s.is_success()
                    && answer
                        .get("errors")
                        .is_none_or(|e| e.as_array().is_some_and(|a| a.is_empty())) =>
            {
                Ok(answer["data"].clone())
            }
            (s, answer) => Err(anyhow!(
                "POST /api/graphql: {s}: {}",
                answer.get("errors").cloned().unwrap_or(Value::Null)
            )),
        }
    }

    /// Whether the project has the branch: a mirror's history is pushed only when it has none.
    pub async fn has_branch(&self, project: u64, branch: &str) -> Result<bool> {
        Ok(self
            .find::<Value>(&format!(
                "/api/v4/projects/{project}/repository/branches/{}",
                segment(branch)
            ))
            .await?
            .is_some())
    }

    /// A generic package, put file by file if no version of that name is there: true when it was put.
    pub async fn ensure_package(&self, project: u64, p: &Package) -> Result<bool> {
        #[derive(Deserialize)]
        struct Found {
            version: String,
        }
        let list = format!(
            "/api/v4/projects/{project}/packages?package_name={}&package_type=generic",
            segment(&p.name)
        );
        let found: Vec<Found> = self.find(&list).await?.unwrap_or_default();
        if found.iter().any(|f| f.version == p.version) {
            return Ok(false);
        }
        for (file, content) in &p.files {
            let at = format!(
                "/api/v4/projects/{project}/packages/generic/{}/{}/{}",
                segment(&p.name),
                segment(&p.version),
                segment(file)
            );
            match self.put(&at, content.as_bytes().to_vec()).await? {
                s if s.is_success() => {}
                s => return Err(anyhow!("PUT {at}: {s}")),
            }
        }
        Ok(true)
    }

    async fn put(&self, path: &str, body: Vec<u8>) -> Result<StatusCode> {
        let url = self
            .base
            .join(path)
            .with_context(|| format!("{path} is not a path"))?;
        let response = self
            .http
            .put(url)
            .header("PRIVATE-TOKEN", &self.token)
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow!("PUT {path}: {}", e.without_url()))?;
        Ok(response.status())
    }

    /// Runs a pipeline's failed jobs again.
    pub async fn retry_pipeline(&self, project: u64, pipeline: u64) -> Result<()> {
        self.make::<Value>(
            &format!("/api/v4/projects/{project}/pipelines/{pipeline}/retry"),
            json!({}),
        )
        .await?;
        Ok(())
    }

    /// The project's pipelines on `main`, newest first.
    pub async fn pipelines(&self, project: u64) -> Result<Vec<Pipeline>> {
        Ok(self
            .find(&format!("/api/v4/projects/{project}/pipelines?ref=main"))
            .await?
            .unwrap_or_default())
    }
}
