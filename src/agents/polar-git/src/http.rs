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

//! git smart HTTP for people's repositories (docs/architecture/polar-git.md): `info/refs`, `git-upload-pack` and
//! `git-receive-pack`, served in process as the record store serves its own (`polar_git_server::git`). Every request
//! is judged before git's protocol is spoken: a fetch asks `git-read`; a push to a repository that is not there asks
//! `git-create`, and makes it, its owner the pusher; and each ref a push moves asks what it does (`edge::classify`),
//! judged in the push's quarantine, so a refused push leaves nothing. A refusal is said before whether a repository
//! exists, so nobody learns of one they may not read. Each is reported (`events`).

use crate::edge::{Asker, Who, classify};
use crate::events::{GitDone, GitEvent, RefMoved, Reporter};
use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use bytes::Bytes;
use polar_git_server::git::{GitRunner, Service};
use polar_git_server::http::{
    PeerCertificate, PeerIdentity, git_failure, git_response, protocol, refuse, repo_name,
    request_body, same_commands,
};
use polar_git_server::pktline::parse_ref_updates;
use polar_git_server::store::RepoStore;
use polar_policy::git::GitAction;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

pub const INFO_REFS_ROUTE: &str = "/:repo/info/refs";
pub const UPLOAD_PACK_ROUTE: &str = "/:repo/git-upload-pack";
pub const RECEIVE_PACK_ROUTE: &str = "/:repo/git-receive-pack";

#[derive(Clone)]
pub struct PolarGitState {
    pub store: RepoStore,
    pub runner: GitRunner,
    pub asker: Arc<dyn Asker>,
    pub reporter: Arc<dyn Reporter>,
    /// The largest request body, compressed or not.
    pub max_body: usize,
}

pub fn router(state: PolarGitState) -> Router {
    let limit = state.max_body;
    Router::new()
        .route(INFO_REFS_ROUTE, get(info_refs))
        .route(UPLOAD_PACK_ROUTE, post(upload_pack))
        .route(RECEIVE_PACK_ROUTE, post(receive_pack))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

fn who(identity: &PeerIdentity, certificate: &PeerCertificate) -> Who {
    Who::of(&identity.0, &certificate.0)
}

/// Asks whether `who` may do `action` to `repo`, its owner as the repository records it; a refusal said and answered
/// 403, before anything about whether the repository is there.
async fn allowed(
    state: &PolarGitState,
    who: &Who,
    action: GitAction,
    repo: &str,
) -> Result<(), Box<Response>> {
    let owner = state.store.owner(repo).await.ok().flatten();
    if state.asker.may(who, action, repo, owner.as_deref()).await {
        return Ok(());
    }
    let why = format!("{} may not {} {repo}", who.name, action.name());
    state.reporter.report(GitEvent::now(
        who,
        repo,
        GitDone::Refused {
            asked: action.name().to_string(),
            why: why.clone(),
        },
    ));
    Err(Box::new(refuse(StatusCode::FORBIDDEN, &why)))
}

/// The repository's place, when it is there.
fn place(state: &PolarGitState, repo: &str) -> Result<std::path::PathBuf, Box<Response>> {
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

async fn info_refs(
    State(state): State<PolarGitState>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    axum::Extension(certificate): axum::Extension<PeerCertificate>,
    Path(repo): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let repo = repo_name(&repo);
    let who = who(&identity, &certificate);
    // Only the smart protocol is served; there is no dumb-HTTP fallback.
    let Some(service) = query.get("service").and_then(|s| Service::from_query(s)) else {
        return refuse(StatusCode::FORBIDDEN, "the smart protocol is required");
    };
    // A push to a repository that is not there makes it, when its pusher may: they own it.
    if service == Service::ReceivePack
        && !state.store.exists(repo)
        && polar_git_server::store::valid_name(repo)
    {
        if let Err(r) = allowed(&state, &who, GitAction::Create, repo).await {
            return *r;
        }
        match state.store.create_owned(repo, &who.identity).await {
            Ok(polar_git_server::store::Created::New) => {
                state
                    .reporter
                    .report(GitEvent::now(&who, repo, GitDone::Created))
            }
            Ok(_) => {}
            Err(e) => {
                warn!(repo, error = %e, "a repository could not be made");
                return refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "the repository could not be made",
                );
            }
        }
    }
    // Seeing a repository's refs is reading it, for a push as for a fetch; what a push may move is judged ref by ref.
    if let Err(r) = allowed(&state, &who, GitAction::Read, repo).await {
        return *r;
    }
    let path = match place(&state, repo) {
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

async fn upload_pack(
    State(state): State<PolarGitState>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    axum::Extension(certificate): axum::Extension<PeerCertificate>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo = repo_name(&repo);
    let who = who(&identity, &certificate);
    if let Err(r) = allowed(&state, &who, GitAction::Read, repo).await {
        return *r;
    }
    let path = match place(&state, repo) {
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
        Ok(out) => {
            state
                .reporter
                .report(GitEvent::now(&who, repo, GitDone::Read));
            git_response(Service::UploadPack.content_type(), out)
        }
        Err(e) => git_failure(e),
    }
}

async fn receive_pack(
    State(state): State<PolarGitState>,
    axum::Extension(identity): axum::Extension<PeerIdentity>,
    axum::Extension(certificate): axum::Extension<PeerCertificate>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let repo = repo_name(&repo).to_string();
    let who = who(&identity, &certificate);
    if let Err(r) = allowed(&state, &who, GitAction::Read, &repo).await {
        return *r;
    }
    let path = match place(&state, &repo) {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let body = match request_body(&headers, body, state.max_body) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let (updates, _) = match parse_ref_updates(&body) {
        Ok(parsed) => parsed,
        Err(e) => return refuse(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let owner = state.store.owner(&repo).await.ok().flatten();
    let runtime = tokio::runtime::Handle::current();
    let asker = state.asker.clone();
    let judged_by = who.clone();
    let named = repo.clone();
    let moved = Arc::new(std::sync::Mutex::new(Vec::new()));
    let refused = Arc::new(std::sync::Mutex::new(None::<(String, String)>));
    let (moved_by, refused_by) = (moved.clone(), refused.clone());
    // Each ref, judged against the push's objects in quarantine, before any ref moves; one refused refuses the push.
    let judge = move |quarantined: &gix::Repository,
                      commands: &[gix_serve::receive_pack::Command]| {
        if !same_commands(&updates, commands) {
            return Err("the commands were not read alike".to_string());
        }
        let mut taken = Vec::new();
        for update in &updates {
            let action = match classify(quarantined, update) {
                Ok(action) => action,
                Err(why) => {
                    *refused_by.lock().expect("lock") = Some((update.refname.clone(), why.clone()));
                    return Err(why);
                }
            };
            let may = runtime.block_on(asker.may(&judged_by, action, &named, owner.as_deref()));
            if !may {
                let why = format!(
                    "{} may not {} {} in {named}",
                    judged_by.name,
                    action.name(),
                    update.refname
                );
                *refused_by.lock().expect("lock") = Some((action.name().to_string(), why.clone()));
                return Err(why);
            }
            taken.push(RefMoved {
                refname: update.refname.clone(),
                old: update.old.clone(),
                new: update.new.clone(),
                action: action.name().to_string(),
            });
        }
        *moved_by.lock().expect("lock") = taken;
        Ok(())
    };
    let served = state.runner.receive_pack(&path, body, judge).await;
    if let Some((asked, why)) = refused.lock().expect("lock").take() {
        state
            .reporter
            .report(GitEvent::now(&who, &repo, GitDone::Refused { asked, why }));
    }
    match served {
        Ok((out, made)) => {
            if !made.is_empty() {
                let moved = std::mem::take(&mut *moved.lock().expect("lock"));
                state
                    .reporter
                    .report(GitEvent::now(&who, &repo, GitDone::Pushed { moved }));
            }
            git_response(Service::ReceivePack.content_type(), out)
        }
        Err(e) => git_failure(e),
    }
}
