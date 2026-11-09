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

//! A stand-in registry that behaves as distribution's does (u7c's, `registry:2.8.3`, probed 2026-11-08): a POST with the body
//! and `?digest=` only opens an upload, the upload goes on at the address `Location` names (on a host of its own), a PUT whose
//! body is not its digest is refused, and a manifest is kept by its repository and tag (`<repository>:<tag>`). Any repository.

#![allow(dead_code)]

use build_orchestrator::push::digest_of;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[derive(Default)]
pub struct Held {
    pub blobs: HashMap<String, Vec<u8>>,
    pub manifests: HashMap<String, (String, Vec<u8>)>,
    pub uploads: usize,
    /// Every request, as `METHOD path`.
    pub asked: Vec<String>,
    /// Refuses every blob it is sent.
    pub refusing: bool,
}

#[derive(Clone, Default)]
pub struct Registry(pub Arc<Mutex<Held>>);

impl Respond for Registry {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut held = self.0.lock().unwrap();
        let path = request.url.path().to_string();
        let query: HashMap<String, String> = request.url.query_pairs().into_owned().collect();
        held.asked.push(format!("{} {path}", request.method));
        // `/v2/<repository>/blobs/...` or `/v2/<repository>/manifests/<tag>`, the repository perhaps with a `/` in it.
        let Some(rest) = path.strip_prefix("/v2/") else {
            return ResponseTemplate::new(404);
        };
        let (repository, blob_rest) = rest.split_once("/blobs/").unwrap_or(("", ""));
        let (manifest_repository, tag) = rest.split_once("/manifests/").unwrap_or(("", ""));
        match request.method.as_str() {
            "HEAD" if !repository.is_empty() && !blob_rest.starts_with("uploads/") => {
                // As distribution does: the blob's length, and no body.
                match held.blobs.get(blob_rest) {
                    Some(bytes) => ResponseTemplate::new(200).set_body_bytes(bytes.clone()),
                    None => ResponseTemplate::new(404),
                }
            }
            // A blob, as a build's fetch reads it.
            "GET" if !repository.is_empty() && !blob_rest.starts_with("uploads/") => {
                match held.blobs.get(blob_rest) {
                    Some(bytes) => ResponseTemplate::new(200).set_body_bytes(bytes.clone()),
                    None => ResponseTemplate::new(404),
                }
            }
            // Whatever it is given, a POST only opens an upload: the body is not kept.
            "POST" if !repository.is_empty() && blob_rest == "uploads/" => {
                held.uploads += 1;
                let n = held.uploads;
                ResponseTemplate::new(202).insert_header(
                    "location",
                    format!("http://elsewhere.invalid:5000/v2/{repository}/blobs/uploads/{n}?_state=s{n}").as_str(),
                )
            }
            "PUT" if !repository.is_empty() && blob_rest.starts_with("uploads/") => {
                let Some(digest) = query.get("digest") else {
                    return ResponseTemplate::new(400);
                };
                if held.refusing
                    || !query.contains_key("_state")
                    || digest_of(&request.body) != *digest
                {
                    return ResponseTemplate::new(400);
                }
                held.blobs.insert(digest.clone(), request.body.clone());
                ResponseTemplate::new(201)
            }
            "PUT" if !manifest_repository.is_empty() => {
                let kind = request
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                held.manifests.insert(
                    format!("{manifest_repository}:{tag}"),
                    (kind, request.body.clone()),
                );
                ResponseTemplate::new(201)
            }
            _ => ResponseTemplate::new(404),
        }
    }
}

/// A stand-in registry, served.
pub async fn registry() -> (MockServer, Registry) {
    let server = MockServer::start().await;
    let registry = Registry::default();
    Mock::given(any())
        .respond_with(registry.clone())
        .mount(&server)
        .await;
    (server, registry)
}

/// What a crates host serves, and what it was asked.
#[derive(Default)]
pub struct Served {
    /// Each crate's bytes by its path.
    pub files: HashMap<String, Vec<u8>>,
    /// Every path asked for.
    pub asked: Vec<String>,
}

/// A crates host.
#[derive(Clone, Default)]
pub struct Crates(pub Arc<Mutex<Served>>);

impl Respond for Crates {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut held = self.0.lock().unwrap();
        let path = request.url.path().to_string();
        held.asked.push(path.clone());
        match held.files.get(&path) {
            Some(bytes) => ResponseTemplate::new(200).set_body_bytes(bytes.clone()),
            None => ResponseTemplate::new(404),
        }
    }
}

/// A stand-in crates host, served: each crate's bytes at `/crates/<name>/<name>-<version>.crate`.
pub async fn crates_host() -> (MockServer, Crates) {
    let server = MockServer::start().await;
    let crates = Crates::default();
    Mock::given(any())
        .respond_with(crates.clone())
        .mount(&server)
        .await;
    (server, crates)
}
