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

//! Git over https: gix's blocking client, over an HTTP implementation of this crate's own. Each request goes out by the
//! agent's client (its proxy, the authorities it trusts), and one with the credential by the CryptoActor, which puts the
//! credential on and sends it: the handler never has it (docs/plans/registry/trusted-remotes.md, "credentials are used
//! without being seen"). It does what libgit2 did for the handler before: the credential is offered only when the host
//! asks for one, once, and goes with every request after the host accepted it; a request goes to the judged host and no
//! other, over no weaker connection; a redirect is followed within the host and refused off it; and a fetch is held to
//! its bound. What went wrong is told to the handler, whose failure says it better than gix's error can.

use crate::protocol::http::{MAX_HOPS, not_sent, transport};
use crate::protocol::{CredentialSource, Failure, Target};
use gix_transport::client::blocking_io::http::{GetResponse, Http, PostBodyDataKind, PostResponse};
use reqwest::header::LOCATION;
use reqwest::{StatusCode, Url};
use std::io::{self, BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};

/// The most a request git sends may hold: what it has and wants, which is small next to what comes back.
pub const MAX_POST: usize = 64 * 1024 * 1024;

/// The credential a fetch may present: its name, and the CryptoActor that holds it.
pub(super) struct Login {
    pub name: String,
    pub source: Arc<dyn CredentialSource>,
}

/// gix's way out for one fetch: cloned for each remote it fetches, and each clone the same fetch.
#[derive(Clone)]
pub(super) struct Through(Arc<Shared>);

struct Shared {
    client: reqwest::Client,
    runtime: tokio::runtime::Handle,
    /// Where the request was judged to go.
    judged: Target,
    login: Option<Login>,
    /// The host asked for the credential, and it was presented.
    presented: AtomicBool,
    /// The host accepted it: every request after goes with it.
    accepted: AtomicBool,
    received: AtomicUsize,
    max_fetch: usize,
    /// Where a redirect within the host moved the repository: what gix puts in front of each address after.
    redirected_base: Mutex<Option<String>>,
    /// What the handler is told, which gix's error will not say.
    told: Mutex<Option<Failure>>,
}

impl Through {
    pub(super) fn new(
        client: reqwest::Client,
        runtime: tokio::runtime::Handle,
        judged: Target,
        login: Option<Login>,
        max_fetch: usize,
    ) -> Self {
        Self(Arc::new(Shared {
            client,
            runtime,
            judged,
            login,
            presented: AtomicBool::new(false),
            accepted: AtomicBool::new(false),
            received: AtomicUsize::new(0),
            max_fetch,
            redirected_base: Mutex::new(None),
            told: Mutex::new(None),
        }))
    }

    /// How many bytes the fetch has brought.
    #[cfg(test)]
    pub(super) fn received(&self) -> usize {
        self.0.received.load(Ordering::Relaxed)
    }

    /// What the handler was told, if anything: the first thing that went wrong.
    pub(super) fn told(&self) -> Option<Failure> {
        self.0.told.lock().unwrap().take()
    }

    /// Starts a request on a thread of its own, as gix's own backends do: a POST goes once gix has written its body and
    /// dropped the writer, and what comes back arrives at the readers as it comes.
    fn start(
        &self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        post: bool,
    ) -> gix::error::Result<PostResponse<Incoming, Incoming, Outgoing>> {
        let shared = &self.0;
        let url = Url::parse(url).map_err(|_| refused("the address cannot be read"))?;
        if let Err(failure) = shared.admits(&url) {
            let said = failure.to_string();
            shared.tell(failure);
            return Err(refused(&said));
        }
        let tail = url
            .as_str()
            .strip_prefix(base_url)
            .unwrap_or_default()
            .to_string();
        let headers: Vec<(String, String)> = headers
            .into_iter()
            .filter_map(|line| {
                let (name, value) = line.as_ref().split_once(':')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect();
        let (body_tx, body_rx) = sync_channel(1);
        let (head_tx, head_rx) = sync_channel(1);
        let (piece_tx, piece_rx) = sync_channel(4);
        let shared = self.0.clone();
        std::thread::spawn(move || {
            shared.exchange(Asked {
                post,
                url,
                tail,
                headers,
                body: body_rx,
                head: head_tx,
                pieces: piece_tx,
            })
        });
        Ok(PostResponse {
            post_body: Outgoing {
                body: Vec::new(),
                done: Some(body_tx),
            },
            headers: Incoming::new(head_rx),
            body: Incoming::new(piece_rx),
        })
    }
}

/// A request as gix asked for it, and where what comes back goes.
struct Asked {
    post: bool,
    url: Url,
    /// What follows the repository's address in `url`, so a redirect says where the repository went.
    tail: String,
    headers: Vec<(String, String)>,
    body: Receiver<Vec<u8>>,
    head: SyncSender<io::Result<Vec<u8>>>,
    pieces: SyncSender<io::Result<Vec<u8>>>,
}

impl Shared {
    fn tell(&self, failure: Failure) {
        self.told.lock().unwrap().get_or_insert(failure);
    }

    /// Whether a request may go to `url`: to the judged host, over a connection as strong as the judged one, with no login
    /// of its own.
    fn admits(&self, url: &Url) -> Result<(), Failure> {
        let host = url.host_str().unwrap_or_default();
        if !host.eq_ignore_ascii_case(&self.judged.host)
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Failure::Configuration(
                "git asked to go to a host other than the one judged".to_string(),
            ));
        }
        if self.judged.encrypted && url.scheme() != "https" {
            return Err(Failure::Configuration(
                "git asked to go over a connection that is not encrypted, to a host judged over one that is"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Sends the request, follows what the host says, and hands what comes back to gix's readers.
    fn exchange(&self, asked: Asked) {
        let Ok(body) = asked.body.recv() else {
            return;
        };
        let sent = self.runtime.block_on(self.send(
            asked.post,
            asked.url,
            &asked.tail,
            &asked.headers,
            body,
        ));
        let mut response = match sent {
            Ok(response) => response,
            Err(failure) => {
                let said = failure.to_string();
                self.tell(failure);
                let _ = asked.head.send(Err(io::Error::other(said)));
                return;
            }
        };
        let mut lines = Vec::new();
        for (name, value) in response.headers() {
            lines.extend_from_slice(name.as_str().as_bytes());
            lines.push(b':');
            lines.extend_from_slice(value.as_bytes());
            lines.push(b'\n');
        }
        if asked.head.send(Ok(lines)).is_err() {
            return;
        }
        drop(asked.head);
        loop {
            let piece = match self.runtime.block_on(response.chunk()) {
                Ok(Some(piece)) => piece,
                Ok(None) => return,
                Err(e) => {
                    let failure = transport(e);
                    let said = failure.to_string();
                    self.tell(failure);
                    let _ = asked.pieces.send(Err(io::Error::other(said)));
                    return;
                }
            };
            let total = self.received.fetch_add(piece.len(), Ordering::Relaxed) + piece.len();
            if total > self.max_fetch {
                let failure = Failure::Transient(format!(
                    "the fetch brought more than the {} bytes one may",
                    self.max_fetch
                ));
                let said = failure.to_string();
                self.tell(failure);
                let _ = asked.pieces.send(Err(io::Error::other(said)));
                return;
            }
            if asked.pieces.send(Ok(piece.to_vec())).is_err() {
                return;
            }
        }
    }

    /// The response to the request, after any redirect within the host and any login the host asked for.
    async fn send(
        &self,
        post: bool,
        mut url: Url,
        tail: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response, Failure> {
        let build = |url: &Url| {
            let mut request = if post {
                self.client.post(url.clone()).body(body.clone())
            } else {
                self.client.get(url.clone())
            };
            for (name, value) in headers {
                request = request.header(name.as_str(), value.as_str());
            }
            request.build().map_err(transport)
        };
        for _ in 0..=MAX_HOPS {
            let response = self.with_login_if_asked(build(&url)?, &build, &url).await?;
            let status = response.status();
            if status.is_redirection()
                && let Some(location) = response.headers().get(LOCATION)
            {
                let next = location
                    .to_str()
                    .ok()
                    .and_then(|location| url.join(location).ok())
                    .ok_or_else(|| {
                        Failure::Transient(
                            "a redirect gave an address that cannot be read".to_string(),
                        )
                    })?;
                // libgit2 followed a redirect within the host and refused one off it; so does this.
                if self.admits(&next).is_err() {
                    return Err(Failure::Transient(
                        "the repository's host redirected to another host, and git follows no redirect off it"
                            .to_string(),
                    ));
                }
                if !post && let Some(base) = next.as_str().strip_suffix(tail) {
                    *self.redirected_base.lock().unwrap() = Some(base.to_string());
                }
                url = next;
                continue;
            }
            if !status.is_success() {
                return Err(Failure::Transient(format!(
                    "the repository's host answered {status}"
                )));
            }
            return Ok(response);
        }
        Err(Failure::Transient(format!(
            "more than {MAX_HOPS} redirects"
        )))
    }

    /// Sends `request`: with the credential once the host has accepted it; otherwise without, and when the host asks for
    /// one, again with it, the first time it asks.
    async fn with_login_if_asked(
        &self,
        request: reqwest::Request,
        build: &impl Fn(&Url) -> Result<reqwest::Request, Failure>,
        url: &Url,
    ) -> Result<reqwest::Response, Failure> {
        if let Some(login) = self.login.as_ref()
            && self.accepted.load(Ordering::Relaxed)
        {
            return self.with_login(login, request).await;
        }
        let response = self.client.execute(request).await.map_err(transport)?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let Some(login) = &self.login else {
            return Err(Failure::Transient(
                "the repository asks for a credential, and names none".to_string(),
            ));
        };
        if self.presented.swap(true, Ordering::Relaxed) {
            return Err(asked_again());
        }
        let response = self.with_login(login, build(url)?).await?;
        self.accepted.store(true, Ordering::Relaxed);
        Ok(response)
    }

    /// Sends `request` by the CryptoActor, with the credential on it. Asked again, the credential was refused.
    async fn with_login(
        &self,
        login: &Login,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, Failure> {
        let sent = login
            .source
            .send_git(login.name.clone(), request, self.client.clone())
            .await
            .map_err(|e| not_sent(&login.name, e))?;
        if sent.response.status() == StatusCode::UNAUTHORIZED {
            return Err(asked_again());
        }
        Ok(sent.response)
    }
}

fn asked_again() -> Failure {
    Failure::CredentialRefused(
        "the repository's host asked again after it was presented".to_string(),
    )
}

/// An error for gix, saying `why`. The handler's own failure is what it was told.
fn refused(why: &str) -> gix::error::Error {
    gix::error::Error::from_error(io::Error::new(
        io::ErrorKind::PermissionDenied,
        why.to_string(),
    ))
}

impl Http for Through {
    type Headers = Incoming;
    type ResponseBody = Incoming;
    type PostBody = Outgoing;

    fn get(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> gix::error::Result<GetResponse<Incoming, Incoming>> {
        // Its body is empty, and goes as the writer is dropped here.
        self.start(url, base_url, headers, false).map(Into::into)
    }

    fn post(
        &mut self,
        url: &str,
        base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        _: PostBodyDataKind,
    ) -> gix::error::Result<PostResponse<Incoming, Incoming, Outgoing>> {
        self.start(url, base_url, headers, true)
    }

    /// What gix's configuration says of the way out is not taken: the agent's client says it.
    fn configure(&mut self, _: &dyn std::any::Any) -> gix::error::Result {
        Ok(())
    }

    fn redirected_base_url(&self) -> Option<String> {
        self.0.redirected_base.lock().unwrap().clone()
    }
}

/// What git writes to send, kept until gix drops it, and then sent.
pub(super) struct Outgoing {
    body: Vec<u8>,
    done: Option<SyncSender<Vec<u8>>>,
}

impl Write for Outgoing {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.body.len() + bytes.len() > MAX_POST {
            return Err(io::Error::other(format!(
                "git would send more than {MAX_POST} bytes"
            )));
        }
        self.body.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(std::mem::take(&mut self.body));
        }
    }
}

/// What comes back, as it arrives: the head's lines, or the body's pieces. It ends when the sender is gone.
pub(super) struct Incoming {
    from: Receiver<io::Result<Vec<u8>>>,
    piece: Vec<u8>,
    at: usize,
}

impl Incoming {
    fn new(from: Receiver<io::Result<Vec<u8>>>) -> Self {
        Self {
            from,
            piece: Vec::new(),
            at: 0,
        }
    }
}

impl Read for Incoming {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Incoming {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.at == self.piece.len() {
            match self.from.recv() {
                Ok(Ok(piece)) => {
                    self.piece = piece;
                    self.at = 0;
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    self.piece.clear();
                    self.at = 0;
                    break;
                }
            }
        }
        Ok(&self.piece[self.at..])
    }

    fn consume(&mut self, n: usize) {
        self.at = (self.at + n).min(self.piece.len());
    }
}

/// Brings `request`'s clone up to date over https, through `through`: libgit2 makes a new clone's repository and its
/// `origin` as it always has, gix fetches each remote, and a new clone's `HEAD` is set as libgit2's clone sets it. A
/// new clone that fails is removed, as libgit2's was.
pub(super) fn fetch(request: &super::Request, through: Through) -> Result<super::Fetched, Failure> {
    let fresh = !request.clone_at.exists();
    let fetched = fetch_into(request, &through, fresh);
    if let Err(said) = fetched {
        if fresh {
            let _ = std::fs::remove_dir_all(&request.clone_at);
        }
        return Err(through.told().unwrap_or(Failure::Transient(said)));
    }
    let repository = git2::Repository::open_bare(&request.clone_at)
        .map_err(|e| Failure::Transient(e.message().to_string()))?;
    Ok(super::Fetched { repository })
}

fn fetch_into(request: &super::Request, through: &Through, fresh: bool) -> Result<(), String> {
    let git2_said = |e: git2::Error| e.message().to_string();
    let names = if fresh {
        let made = git2::Repository::init_bare(&request.clone_at).map_err(git2_said)?;
        made.remote("origin", &request.url).map_err(git2_said)?;
        vec!["origin".to_string()]
    } else {
        request.remotes.clone()
    };
    let repository =
        gix::open_opts(&request.clone_at, gix::open::Options::isolated()).map_err(|e| said(&e))?;
    let mut head = None;
    for name in &names {
        let remote = repository
            .find_remote(name.as_str())
            .map_err(|e| said(&e))?;
        let url = remote
            .url(gix::remote::Direction::Fetch)
            .ok_or_else(|| format!("the remote {name} has no address"))?
            .clone();
        let transport = gix_transport::client::blocking_io::http::connect_http(
            through.clone(),
            url,
            gix_transport::Protocol::V2,
            false,
        );
        let mut fetching = remote
            .to_connection_with_transport(transport)
            // The way in is the CryptoActor's, through `through`: no helper is ever run.
            .with_credentials(|_| Ok(None))
            .prepare_fetch(gix::progress::Discard, head_too())
            .map_err(|e| said(&e))?;
        if let Some(depth) = request.depth {
            let depth = u32::try_from(depth)
                .ok()
                .and_then(std::num::NonZeroU32::new)
                .ok_or_else(|| format!("a depth of {depth} cannot be asked for"))?;
            fetching = fetching.with_shallow(gix::protocol::fetch::Shallow::DepthAtRemote(depth));
        }
        let outcome = fetching
            .receive(gix::progress::Discard, &AtomicBool::new(false))
            .map_err(|e| said(&e))?;
        if head.is_none() {
            head = outcome.ref_map.remote_refs.iter().find_map(|r| match r {
                gix::protocol::handshake::Ref::Symbolic {
                    full_ref_name,
                    target,
                    ..
                } if full_ref_name == "HEAD" => Some(target.to_string()),
                _ => None,
            });
        }
    }
    if fresh && let Some(branch) = head.as_deref().and_then(|h| h.strip_prefix("refs/heads/")) {
        let made = git2::Repository::open_bare(&request.clone_at).map_err(git2_said)?;
        let tracking = format!("refs/remotes/origin/{branch}");
        let tip = made.refname_to_id(&tracking).map_err(git2_said)?;
        let local = format!("refs/heads/{branch}");
        made.reference(&local, tip, true, "clone")
            .map_err(git2_said)?;
        made.set_head(&local).map_err(git2_said)?;
        made.reference_symbolic("refs/remotes/origin/HEAD", &tracking, true, "clone")
            .map_err(git2_said)?;
    }
    Ok(())
}

/// The refs to ask for: the remote's own, and `HEAD` beside them, which a server speaking git's second protocol lists
/// only when asked, and which says the default branch a new clone's `HEAD` names.
fn head_too() -> gix::remote::ref_map::Options {
    gix::remote::ref_map::Options {
        extra_refspecs: vec![
            gix::refspec::parse("HEAD".into(), gix::refspec::parse::Operation::Fetch)
                .expect("HEAD is a refspec")
                .to_owned(),
        ],
        ..Default::default()
    }
}

/// An error and every cause beneath it.
fn said(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn through(host: &str, encrypted: bool) -> Through {
        Through::new(
            reqwest::Client::new(),
            tokio::runtime::Handle::current(),
            Target {
                host: host.to_string(),
                encrypted,
                access: None,
                reaches_node: Vec::new(),
                namespace: None,
            },
            None,
            super::super::MAX_FETCH,
        )
    }

    /// A request goes to the judged host alone, by any spelling of its name, with no login of its own, and over a
    /// connection no weaker than the judged one.
    #[tokio::test]
    async fn only_the_judged_host_is_admitted_with_no_login_and_no_weaker_connection() {
        let over_tls = through("git.example.org", true);
        let admits = |url: &str| over_tls.0.admits(&Url::parse(url).unwrap()).is_ok();
        assert!(admits("https://git.example.org/r.git/info/refs"));
        assert!(admits("https://GIT.example.org/r.git"));
        for refused in [
            "https://elsewhere.example.org/r.git",
            "https://user@git.example.org/r.git",
            "https://:password@git.example.org/r.git",
            "https://user:password@git.example.org/r.git",
            "http://git.example.org/r.git",
        ] {
            assert!(!admits(refused), "{refused}");
        }
        let plain = through("git.example.org", false);
        assert!(
            plain
                .0
                .admits(&Url::parse("http://git.example.org/r.git").unwrap())
                .is_ok()
        );
        assert!(
            plain
                .0
                .admits(&Url::parse("https://git.example.org/r.git").unwrap())
                .is_ok()
        );
    }

    /// What git sends is held to [`MAX_POST`]: up to it, and not a byte past it, however it is written.
    #[test]
    fn what_git_sends_is_held_to_its_bound() {
        let (done, sent) = sync_channel(1);
        let mut outgoing = Outgoing {
            body: Vec::new(),
            done: Some(done),
        };
        outgoing.write_all(&vec![b'x'; MAX_POST - 1]).unwrap();
        outgoing.write_all(b"y").unwrap();
        assert!(outgoing.write(b"z").is_err());
        drop(outgoing);
        assert_eq!(sent.recv().unwrap().len(), MAX_POST);

        let (done, _sent) = sync_channel(1);
        let mut outgoing = Outgoing {
            body: Vec::new(),
            done: Some(done),
        };
        assert!(outgoing.write(&vec![b'x'; MAX_POST + 1]).is_err());
    }
}
