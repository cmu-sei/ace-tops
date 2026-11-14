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

//! Git smart HTTP: `info/refs`, `git-upload-pack` and `git-receive-pack`. The caller's identity
//! arrives as an extension set by the TLS listener; this module trusts nothing else about who is
//! asking. Every request is authorized before git's protocol is spoken, and a push before its pack is read.

use crate::access::{Access, Authorizer, Identity, RuntimeAcl, authorize_push};
use crate::git::{GitError, GitRunner, Service};
use crate::notify::{Notifier, RepoChanged};
use crate::pktline::{RefUpdate, parse_ref_updates};
use crate::store::RepoStore;
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use bytes::Bytes;
use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;
use tracing::{info, warn};

/// The identity the TLS listener took from the client certificate.
#[derive(Debug, Clone)]
pub struct PeerIdentity(pub String);

#[derive(Clone)]
pub struct ServerState {
    pub store: RepoStore,
    pub authorizer: Arc<dyn Authorizer>,
    /// The access lists of repositories created at runtime; normally the same object as
    /// `authorizer`.
    pub runtime: Arc<RuntimeAcl>,
    pub runner: GitRunner,
    pub notifier: Arc<dyn Notifier>,
    /// The largest request body, compressed or not.
    pub max_body: usize,
    /// The repositories whose every commit must be signed, and by whom.
    pub signed: Arc<crate::signed::SignedRepos>,
    /// The store's logs, served to people as C2SP tlog-tiles under `/logs/<log>/`; none, and no log is served.
    pub logs: Option<ractor::ActorRef<crate::logs::LogsMessage>>,
}

pub fn router(state: ServerState) -> Router {
    let limit = state.max_body;
    Router::new()
        .route("/admin/repos/:name", put(crate::admin::create_repo))
        .route("/logs/:log/checkpoint", get(log_checkpoint))
        .route("/logs/:log/tile/*path", get(log_tile))
        .route("/:repo/info/refs", get(info_refs))
        .route("/:repo/git-upload-pack", post(upload_pack))
        .route(
            polar_git_server_common::RECEIVE_PACK_ROUTE,
            post(receive_pack),
        )
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

pub(crate) fn refuse(status: StatusCode, why: &str) -> Response {
    (status, format!("{why}\n")).into_response()
}

fn git_response(content_type: String, body: Vec<u8>) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CACHE_CONTROL,
            "no-cache, max-age=0, must-revalidate",
        )
        .body(Body::from(body))
        .expect("a response with static headers")
}

fn git_failure(e: GitError) -> Response {
    warn!(error = %e, "git failed");
    refuse(StatusCode::INTERNAL_SERVER_ERROR, "git failed")
}

/// `repo.git` and `repo` name the same repository.
fn repo_name(segment: &str) -> &str {
    segment.strip_suffix(".git").unwrap_or(segment)
}

fn protocol(headers: &HeaderMap) -> Option<&str> {
    headers.get("git-protocol").and_then(|v| v.to_str().ok())
}

/// Authorizes `who` for `access` on `repo` and finds the repository. Denial is reported before
/// existence, so a caller learns nothing about repositories it may not touch.
fn open(
    state: &ServerState,
    who: &PeerIdentity,
    repo: &str,
    access: Access,
) -> Result<std::path::PathBuf, Box<Response>> {
    let identity = Identity(who.0.clone());
    if !state.authorizer.allows(&identity, repo, access) {
        info!(who = %who.0, repo, ?access, "denied");
        return Err(Box::new(refuse(StatusCode::FORBIDDEN, "not permitted")));
    }
    if !state.store.exists(repo) {
        return Err(Box::new(refuse(
            StatusCode::NOT_FOUND,
            "no such repository",
        )));
    }
    state
        .store
        .path(repo)
        .map_err(|_| Box::new(refuse(StatusCode::NOT_FOUND, "no such repository")))
}

/// The store's logs, for `who` to read `log`: a log the store serves to people, whose repository `who` may read
/// ([`crate::logs::governing_repo`]). Denial is reported before anything about the log.
fn log_reader(
    state: &ServerState,
    who: &PeerIdentity,
    log: &str,
) -> Result<ractor::ActorRef<crate::logs::LogsMessage>, Box<Response>> {
    let Some(repo) = crate::logs::governing_repo(log) else {
        return Err(Box::new(refuse(StatusCode::NOT_FOUND, "no such log")));
    };
    if !state
        .authorizer
        .allows(&Identity(who.0.clone()), repo, Access::Read)
    {
        info!(who = %who.0, log, "denied a log");
        return Err(Box::new(refuse(StatusCode::FORBIDDEN, "not permitted")));
    }
    state
        .logs
        .clone()
        .ok_or_else(|| Box::new(refuse(StatusCode::NOT_FOUND, "no such log")))
}

fn log_response(content_type: &str, cache: &str, body: Vec<u8>) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, cache)
        .body(Body::from(body))
        .expect("a response with static headers")
}

fn log_unavailable(why: impl std::fmt::Display) -> Response {
    warn!(%why, "a log could not be read");
    refuse(StatusCode::SERVICE_UNAVAILABLE, "the log could not be read")
}

/// The log's latest checkpoint the witness co-signed (record-store.md, "Bite 5": readers require it); never cached past
/// now, since the log grows. Before the witness first co-signed one, there is none to serve.
async fn log_checkpoint(
    State(state): State<ServerState>,
    axum::Extension(who): axum::Extension<PeerIdentity>,
    Path(log): Path<String>,
) -> Response {
    let logs = match log_reader(&state, &who, &log) {
        Ok(logs) => logs,
        Err(r) => return *r,
    };
    match ractor::call!(logs, |reply| crate::logs::LogsMessage::Cosigned {
        log: log.clone(),
        reply
    }) {
        Ok(Some(note)) => log_response(
            "text/plain; charset=utf-8",
            "no-cache, max-age=0",
            note.into_bytes(),
        ),
        Ok(None) => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "the log is not yet witnessed",
        ),
        Err(e) => log_unavailable(e),
    }
}

/// A tile or entry bundle of the log. What a tile holds never changes, so it may be kept; only by its reader, since
/// reading it was authorized.
async fn log_tile(
    State(state): State<ServerState>,
    axum::Extension(who): axum::Extension<PeerIdentity>,
    Path((log, path)): Path<(String, String)>,
) -> Response {
    let logs = match log_reader(&state, &who, &log) {
        Ok(logs) => logs,
        Err(r) => return *r,
    };
    let path = format!("tile/{}", path.trim_start_matches('/'));
    match ractor::call!(logs, |reply| crate::logs::LogsMessage::Tile {
        log: log.clone(),
        path,
        reply
    }) {
        Ok(Ok(Some(bytes))) => log_response(
            "application/octet-stream",
            "private, max-age=31536000, immutable",
            bytes,
        ),
        Ok(Ok(None)) => refuse(StatusCode::NOT_FOUND, "no such tile"),
        Ok(Err(why)) => log_unavailable(why),
        Err(e) => log_unavailable(e),
    }
}

fn access_for(service: Service) -> Access {
    match service {
        Service::UploadPack => Access::Read,
        Service::ReceivePack => Access::Write,
    }
}

async fn info_refs(
    State(state): State<ServerState>,
    axum::Extension(who): axum::Extension<PeerIdentity>,
    Path(repo): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let repo = repo_name(&repo);
    // Only the smart protocol is served; there is no dumb-HTTP fallback.
    let Some(service) = query.get("service").and_then(|s| Service::from_query(s)) else {
        return refuse(StatusCode::FORBIDDEN, "the smart protocol is required");
    };
    let path = match open(&state, &who, repo, access_for(service)) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    match state
        .runner
        .advertise(&path, service, protocol(&headers))
        .await
    {
        Ok(body) => git_response(service.advertisement_content_type(), body),
        Err(e) => git_failure(e),
    }
}

/// Inflates a gzip-encoded request body, refusing one that grows past `limit`.
fn inflate(body: &[u8], limit: usize) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| ())?;
    if out.len() > limit { Err(()) } else { Ok(out) }
}

fn request_body(headers: &HeaderMap, body: Bytes, limit: usize) -> Result<Vec<u8>, Box<Response>> {
    let gzip = headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("gzip"));
    if gzip {
        inflate(&body, limit)
            .map_err(|_| Box::new(refuse(StatusCode::BAD_REQUEST, "bad or oversized body")))
    } else {
        Ok(body.to_vec())
    }
}

async fn upload_pack(
    State(state): State<ServerState>,
    axum::Extension(who): axum::Extension<PeerIdentity>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo = repo_name(&repo);
    let path = match open(&state, &who, repo, Access::Read) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let body = match request_body(&headers, body, state.max_body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    match state
        .runner
        .upload_pack(&path, protocol(&headers), body)
        .await
    {
        Ok(out) => git_response(Service::UploadPack.content_type(), out),
        Err(e) => git_failure(e),
    }
}

async fn receive_pack(
    State(state): State<ServerState>,
    axum::Extension(who): axum::Extension<PeerIdentity>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo = repo_name(&repo);
    let path = match open(&state, &who, repo, Access::Write) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let body = match request_body(&headers, body, state.max_body) {
        Ok(b) => b,
        Err(r) => return *r,
    };

    // The commands precede the pack: decide before it is read.
    let (updates, _) = match parse_ref_updates(&body) {
        Ok(parsed) => parsed,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    if let Err(why) = authorize_push(
        state.authorizer.as_ref(),
        &Identity(who.0.clone()),
        repo,
        &updates,
    ) {
        info!(who = %who.0, repo, %why, "push denied");
        return refuse(StatusCode::FORBIDDEN, &why);
    }

    let now = crate::signed::wall_clock();
    let signed = Arc::clone(&state.signed);
    let (name, pusher) = (repo.to_string(), who.0.clone());
    let logs = state.logs.clone();
    let runtime = tokio::runtime::Handle::current();
    let judge = move |quarantined: &gix::Repository,
                      commands: &[gix_serve::receive_pack::Command]| {
        // What is taken is what was authorized: gix-serve read the same commands from the body.
        if !same_commands(&updates, commands) {
            return Err("the commands were not read alike".to_string());
        }
        // A record in the evidence repository is verified as of the commit that added it: that time is the server's
        // word (docs/architecture/key-custody.md, "Workload signing keys", item 7).
        if name == polar_git_server_common::EVIDENCE_REPO
            && let Err(why) = crate::evidence::check_pushed_times(quarantined, &updates, now)
        {
            warn!(who = %pusher, repo = %name, %why, "push refused: a commit not made about now");
            return Err(why);
        }
        if let Some(policy) = signed.policy_of(&name)
            && let Err(why) = crate::signed::check_push(quarantined, policy, &updates, now)
        {
            warn!(who = %pusher, repo = %name, %why, "push refused: not signed as this repository requires");
            return Err(why);
        }
        // Last, once nothing else refuses it: what the push adds to the evidence repository is appended to the store's
        // evidence log, as the pusher's, before any ref moves; a record the log does not take refuses the push, so the
        // repository never holds a record the log does not (docs/architecture/record-store.md, "Pushes to the log").
        if name == polar_git_server_common::EVIDENCE_REPO
            && let Some(logs) = &logs
        {
            for (path, bytes) in crate::evidence::pushed_records(quarantined, &updates)? {
                let record = String::from_utf8(bytes)
                    .map_err(|_| format!("{path} is not text, so it is no record"))?;
                let appended = runtime.block_on(async {
                    ractor::call!(logs, |reply| crate::logs::LogsMessage::AppendOnce {
                        log: crate::evidence::EVIDENCE_LOG.to_string(),
                        entry: crate::evidence::evidence_entry(&record),
                        submitter: pusher.clone(),
                        reply,
                    })
                });
                match appended {
                    Ok(Ok(_)) => {}
                    Ok(Err(why)) => {
                        warn!(who = %pusher, repo = %name, %path, %why, "push refused: the evidence log did not take a record");
                        return Err(format!(
                            "{path}: the store's evidence log did not take it: {why}"
                        ));
                    }
                    Err(e) => {
                        warn!(who = %pusher, repo = %name, error = %e, "push refused: the store's logs did not answer");
                        return Err(
                            "the store's evidence log did not answer; push again".to_string()
                        );
                    }
                }
            }
        }
        Ok(())
    };
    let (out, made) = match state.runner.receive_pack(&path, body, judge).await {
        Ok(served) => served,
        Err(e) => return git_failure(e),
    };

    // A push is taken whole or not at all; announce what it moved.
    for command in made {
        state
            .notifier
            .repo_changed(RepoChanged {
                repo: repo.to_string(),
                refname: command.name,
                old: command.old.to_string(),
                new: command.new.to_string(),
                pusher: who.0.clone(),
            })
            .await;
    }
    git_response(Service::ReceivePack.content_type(), out)
}

/// Whether gix-serve's commands are the ones authorized: the same updates in the same order.
fn same_commands(authorized: &[RefUpdate], read: &[gix_serve::receive_pack::Command]) -> bool {
    authorized.len() == read.len()
        && authorized.iter().zip(read).all(|(a, r)| {
            a.refname == r.name
                && a.old.eq_ignore_ascii_case(&r.old.to_string())
                && a.new.eq_ignore_ascii_case(&r.new.to_string())
        })
}
