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

//! The git protocol: a repository brought up to date in the agent's cache, and a callback that reads it. Over https gix
//! fetches, through an HTTP implementation whose requests the agent's client sends, and the CryptoActor when one goes with
//! the credential ([`https`]): the handler never has a token or a password. Over ssh libgit2 still fetches, with the key
//! the CryptoActor gives for an ssh host alone, until custody signs for it. libgit2 does its own I/O and asks for the key
//! through a callback, so that callback is here and nowhere else: it offers the key for the host the request was judged
//! for, once, and only over a connection to that host. What was fetched is read with libgit2 either way. libgit2's options
//! are global to the process, so its CA and timeouts are set once, here, when the agent starts
//! (docs/architecture/protocol-handlers.md, "The protocols").
//!
//! Over ssh (docs/architecture/build-orchestrator.md, "Revised 2026-11-08, the source"), a repository is fetched only with
//! a credential that is an ssh key, whose signed binding pins the server's host key: libgit2 shows the handler the key the
//! server presents before anything is offered, and the fetch ends there if it is not the pinned one. There is no trust on
//! first use, no known-hosts file, and no ssh through the egress proxy, which carries http only.

use super::probe::{Probed, Reach, classify};
use super::{
    CredentialSource, Exchange, Failure, Pending, Protocol, ProtocolKind, Started, Target,
};
use async_trait::async_trait;
use base64::Engine;
use git2::{
    CertificateCheckStatus, Cred, CredentialType, Direction, FetchOptions, ProxyOptions,
    RemoteCallbacks, RemoteRedirect, Repository,
};
use polar::egress::Egress;

mod https;
use polar_crypto::CryptoError;
use polar_crypto::registry::{GitCredential, SecretKind};
use reqwest::Url;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// How long opening a connection may take. A host that has not answered by then is as good as unreachable.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one read of the connection or one write to it may take: without a bound, a host that stops answering in the
/// middle of a fetch leaves it waiting for ever. A long fetch that keeps moving is not held to it.
/// The two go together: libgit2 makes the socket non-blocking for the first, and with no second every read fails at once.
pub const SERVER_TIMEOUT: Duration = Duration::from_secs(120);
/// The most one fetch may bring, in bytes: it goes to disk, so this is what one repository can cost the agent's cache.
pub const MAX_FETCH: usize = 16 * 1024 * 1024 * 1024;
/// How long an operation's `read` has with what was fetched: reading a long history takes a while.
const READ_BUDGET: Duration = Duration::from_secs(300);

/// What an operation says it wants: this repository up to date in the clone at this path.
#[derive(Debug, Clone)]
pub struct Request {
    url: String,
    clone_at: PathBuf,
    remotes: Vec<String>,
    depth: Option<usize>,
}

impl Request {
    /// `url` cloned bare at `clone_at`, or if there is a clone there already, each of `remotes` fetched into it. `depth`
    /// limits how much of the history comes, as `git clone --depth` does.
    pub fn new(
        url: impl Into<String>,
        clone_at: impl Into<PathBuf>,
        remotes: Vec<String>,
        depth: Option<usize>,
    ) -> Self {
        Self {
            url: url.into(),
            clone_at: clone_at.into(),
            remotes,
            depth,
        }
    }
}

/// What came back: the clone, up to date. A credential is never written to it.
pub struct Fetched {
    pub repository: Repository,
}

/// What a judgment reads of a repository's address: the same reading as an HTTP request's, and libgit2 must read it the
/// same way, since it reads the address for itself. So the text between `://` and the first `/`, `?` or `#` must be the host
/// and a port and nothing else, not a backslash, an `@` or an empty port that two parsers could take differently.
fn target_of(address: &str) -> Result<Target, String> {
    let url = Url::parse(address).map_err(|_| "the address cannot be read".to_string())?;
    let target = match url.scheme() {
        "ssh" => ssh_target(&url)?,
        _ => super::http::target_of(&url)?,
    };
    let authority = address
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .unwrap_or_default();
    let (name, port) = match authority.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (authority, None),
    };
    let plain = port.is_none_or(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if !plain || !name.eq_ignore_ascii_case(&target.host) {
        return Err("the address is not one git and this agent are sure to read alike".to_string());
    }
    Ok(target)
}

/// What a judgment reads of an ssh address: its host, a host name or an IPv4 address written plainly (an ssh address's host
/// is not read as an HTTP one's is, so nothing that could be read two ways is taken: no escape, no IPv6 in brackets), and
/// no login, since the user is the credential's. The connection is encrypted.
fn ssh_target(url: &Url) -> Result<Target, String> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the address carries a login of its own".to_string());
    }
    let host = url
        .host_str()
        .filter(|host| {
            !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        })
        .ok_or_else(|| "an ssh address names a host name or an IPv4 address".to_string())?;
    Ok(Target {
        host: host.to_ascii_lowercase(),
        encrypted: true,
        access: None,
        reaches_node: Vec::new(),
        namespace: None,
    })
}

/// A host key's type by its name in ssh, as `known_hosts` and `ssh-keygen -l` write it.
fn key_type(kind: Option<git2::cert::SshHostKeyType>) -> &'static str {
    use git2::cert::SshHostKeyType;
    match kind {
        Some(SshHostKeyType::Rsa) => "ssh-rsa",
        Some(SshHostKeyType::Dss) => "ssh-dss",
        Some(SshHostKeyType::Ecdsa256) => "ecdsa-sha2-nistp256",
        Some(SshHostKeyType::Ecdsa384) => "ecdsa-sha2-nistp384",
        Some(SshHostKeyType::Ecdsa521) => "ecdsa-sha2-nistp521",
        Some(SshHostKeyType::Ed255219) => "ssh-ed25519",
        _ => "unknown",
    }
}

/// The host key a server presented, as `ssh-keygen -l` writes its fingerprint and a binding pins it.
fn fingerprint_of(sha256: &[u8; 32]) -> String {
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha256)
    )
}

/// What the handler needs from `config`: a CA that cannot be used stops the agent, before it does anything, with the
/// variable and the path.
pub(crate) fn start(config: &polar_env::Config) -> Pending<Result<Started, String>> {
    let egress = Egress::read(config).map_err(|e| e.to_string());
    Box::pin(async move {
        let git = Git::ready(egress?, CONNECT_TIMEOUT, SERVER_TIMEOUT).await?;
        Ok(Arc::new(git) as Started)
    })
}

/// Trusts the CA certificates in the file at `path` for every TLS connection libgit2 makes from now on, beside the ones it
/// trusts already (OpenSSL's default locations: the system bundle).
pub(crate) fn trust_ca_file(path: &Path) -> Result<(), git2::Error> {
    // SAFETY: libgit2's options are global to the process and not synchronised. This is called once, as the agent starts
    // and before any request exists, so no other libgit2 call runs beside it.
    unsafe { git2::opts::set_ssl_cert_file(path) }
}

/// The git protocol, with the way out of the cluster: the client gix sends by, and what libgit2 is told of it.
pub struct Git {
    egress: Egress,
    client: reqwest::Client,
    max_fetch: usize,
}

/// A credential as git has it. Over https its name and the CryptoActor that sends with it; over ssh the key itself, until
/// custody signs for it.
pub struct GitUse(Holding);

enum Holding {
    Sent(https::Login),
    SshKey(GitCredential),
}

/// The client gix sends by: the way out `egress` says, trusting `bundle` beside the system's roots, with a bound on
/// opening a connection and on each read, and following no redirect by itself.
fn client(
    egress: &Egress,
    bundle: &[reqwest::Certificate],
    connect_timeout: Duration,
    server_timeout: Duration,
) -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .read_timeout(server_timeout)
        .redirect(reqwest::redirect::Policy::none());
    egress
        .configure(builder, bundle)
        .and_then(reqwest::ClientBuilder::build)
        .map_err(|e| format!("the git client cannot be built: {e}"))
}

impl Git {
    /// Gives libgit2 the egress CA and the timeouts, for the whole process.
    async fn ready(
        egress: Egress,
        connect_timeout: Duration,
        server_timeout: Duration,
    ) -> Result<Self, String> {
        let bundle = egress.ca_bundle().await.map_err(|e| e.to_string())?;
        if let Some(path) = &egress.ca_cert {
            trust_ca_file(Path::new(path)).map_err(|e| {
                format!("POLAR_EGRESS_CA_CERT {path} could not be given to git: {e}")
            })?;
            tracing::info!(
                "trusting {} egress CA certificate(s) beside the system's",
                bundle.len()
            );
        }
        // SAFETY: as for `trust_ca_file`: once, before any request exists.
        unsafe {
            git2::opts::set_server_connect_timeout_in_milliseconds(
                connect_timeout.as_millis() as i32
            )
            .and_then(|()| {
                git2::opts::set_server_timeout_in_milliseconds(server_timeout.as_millis() as i32)
            })
        }
        .map_err(|e| format!("git could not be given its timeouts: {e}"))?;
        Ok(Self {
            client: client(&egress, &bundle, connect_timeout, server_timeout)?,
            egress,
            max_fetch: MAX_FETCH,
        })
    }

    /// Going out as `egress` says, trusting the tests' CA ([`super::testing::git_ca`]).
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn with_egress(egress: Egress, max_fetch: usize) -> Self {
        let ca = reqwest::Certificate::from_pem(super::testing::git_ca().pem.as_bytes())
            .expect("the tests' CA");
        let client = client(&egress, &[ca], CONNECT_TIMEOUT, SERVER_TIMEOUT).expect("a client");
        Self {
            egress,
            client,
            max_fetch,
        }
    }
}

/// What a clone or a fetch over ssh is given, each time: the key, the bound and the depth. It goes through no proxy.
/// With none libgit2 connects directly: it is not told to look for one, so the process environment never decides.
struct Fetching<'a> {
    credential: Option<&'a GitCredential>,
    /// The host the request was judged for.
    host: &'a str,
    depth: Option<usize>,
    max_fetch: usize,
    /// What a callback knows that libgit2's error will not say.
    told: &'a Cell<Option<Failure>>,
}

impl<'a> Fetching<'a> {
    /// A new set each time: the credential is offered once per connection.
    fn options(&self) -> FetchOptions<'a> {
        let (credential, host, told) = (self.credential, self.host.to_string(), self.told);
        let mut presented = false;
        let mut callbacks = RemoteCallbacks::new();
        // Over ssh, the server's host key against the pins, before anything is offered; over https, libgit2's own check of
        // the certificate. Which of its keys a server shows is negotiated (libgit2 even prefers a type a `known_hosts` file
        // lists), so the binding pins each of them, and the refusal says which was shown: a host key is public.
        let pins = credential
            .map(|credential| credential.host_keys.clone())
            .unwrap_or_default();
        callbacks.certificate_check(move |cert, _| {
            let Some(hostkey) = cert.as_hostkey() else {
                return Ok(CertificateCheckStatus::CertificatePassthrough);
            };
            let shown = hostkey.hash_sha256().map(fingerprint_of);
            if shown.as_ref().is_some_and(|shown| pins.contains(shown)) {
                return Ok(CertificateCheckStatus::CertificateOk);
            }
            told.set(Some(Failure::Configuration(format!(
                "the server's host key is not one its credential pins: it showed its {} key {}",
                key_type(hostkey.hostkey_type()),
                shown.as_deref().unwrap_or("with no SHA-256 fingerprint"),
            ))));
            Err(git2::Error::from_str("host key"))
        });
        callbacks.credentials(move |url, _, allowed| {
            let Some(credential) = credential else {
                told.set(Some(Failure::Transient(
                    "the repository asks for a credential, and names none".to_string(),
                )));
                return Err(git2::Error::from_str("no credential"));
            };
            let asked_by = Url::parse(url).ok();
            let asked_by = asked_by.as_ref().and_then(Url::host_str);
            if !asked_by.is_some_and(|asked_by| asked_by.eq_ignore_ascii_case(&host)) {
                told.set(Some(Failure::Configuration(
                    "git asked for the credential for a host other than the one judged".to_string(),
                )));
                return Err(git2::Error::from_str("another host"));
            }
            // Over ssh libgit2 first asks for the user alone, when the address names none; that presents nothing.
            if allowed == CredentialType::USERNAME {
                return Cred::username(&credential.username);
            }
            // libgit2 asks again only when what it was given was refused, and would go on asking.
            if presented {
                told.set(Some(Failure::CredentialRefused(
                    "the repository's host asked again after it was presented".to_string(),
                )));
                return Err(git2::Error::from_str("refused"));
            }
            presented = true;
            let secret = std::str::from_utf8(&credential.secret)
                .map_err(|_| git2::Error::from_str("the credential is not text"))?;
            // From memory: the key is never written to a file. Only an ssh key is ever given here.
            Cred::ssh_key_from_memory(&credential.username, None, secret, None)
        });
        let max_fetch = self.max_fetch;
        callbacks.transfer_progress(move |progress| {
            let within = progress.received_bytes() <= max_fetch;
            if !within {
                told.set(Some(Failure::Transient(format!(
                    "the fetch brought more than the {max_fetch} bytes one may"
                ))));
            }
            within
        });
        let mut options = FetchOptions::new();
        options.remote_callbacks(callbacks);
        options.follow_redirects(RemoteRedirect::None);
        if let Some(depth) = self.depth {
            options.depth(depth as i32);
        }
        options
    }

    /// Clones or fetches. A fresh clone has fetched everything there is.
    fn bring_up_to_date(&self, request: &Request) -> Result<Repository, git2::Error> {
        if !request.clone_at.exists() {
            let mut builder = git2::build::RepoBuilder::new();
            builder.bare(true);
            builder.fetch_options(self.options());
            return builder.clone(&request.url, &request.clone_at);
        }
        let repository = Repository::open_bare(&request.clone_at)?;
        for name in &request.remotes {
            let mut remote = repository.find_remote(name)?;
            remote.fetch(&[] as &[&str], Some(&mut self.options()), None)?;
        }
        Ok(repository)
    }
}

/// The egress probe's request ([`super::probe`]): the repository's refs, as a fetch begins, with nothing presented. A repository
/// that asks for a login has answered, and is reached. Over ssh it is not made: that needs a key, and a host key pinned.
pub(crate) fn probe(started: Started, url: String, proxied: bool) -> Pending<Probed> {
    Box::pin(async move {
        let Ok(git) = started.downcast::<Git>() else {
            return Probed::new(Reach::Other, "the git protocol did not start as git");
        };
        if Url::parse(&url).is_ok_and(|url| url.scheme() == "ssh") {
            return Probed::new(
                Reach::Other,
                "an ssh address is not probed: it needs a key, and its host key pinned",
            );
        }
        let proxy = git.egress.proxy_for(&url);
        tokio::task::spawn_blocking(move || {
            let asked = Cell::new(false);
            let listed = (|| {
                let mut remote = git2::Remote::create_detached(url.as_str())?;
                let mut callbacks = RemoteCallbacks::new();
                callbacks.credentials(|_, _, _| {
                    asked.set(true);
                    Err(git2::Error::from_str("the probe presents no credential"))
                });
                let mut through = ProxyOptions::new();
                if let Some(proxy) = &proxy {
                    through.url(proxy);
                }
                let connection =
                    remote.connect_auth(Direction::Fetch, Some(callbacks), Some(through))?;
                Ok::<_, git2::Error>(connection.list()?.len())
            })();
            match listed {
                Ok(refs) => Probed::new(Reach::Reached, format!("it listed {refs} refs")),
                Err(_) if asked.get() => Probed::new(
                    Reach::Reached,
                    "it asked for a login, and the probe presents none",
                ),
                Err(e) => classify(e.message(), proxied),
            }
        })
        .await
        .unwrap_or_else(|e| Probed::new(Reach::Other, format!("the probe did not finish: {e}")))
    })
}

impl super::sealed::Sealed for Git {}

#[async_trait]
impl Protocol for Git {
    const KIND: ProtocolKind = ProtocolKind::GIT;
    const BUDGET: Duration = READ_BUDGET;
    type Request = Request;
    type Credential = GitUse;
    type Reply = Fetched;

    fn configured_host(base: &str) -> Result<String, String> {
        target_of(base).map(|target| target.host)
    }

    fn target(request: &Request, _: Option<&str>) -> Result<Target, String> {
        target_of(&request.url)
    }

    async fn credential(
        source: &Arc<dyn CredentialSource>,
        name: String,
        host: String,
    ) -> Result<GitUse, CryptoError> {
        match source.git_kind(name.clone(), host.clone()).await? {
            SecretKind::SshKey => source
                .git(name, host)
                .await
                .map(|key| GitUse(Holding::SshKey(key))),
            _ => Ok(GitUse(Holding::Sent(https::Login {
                name,
                source: source.clone(),
            }))),
        }
    }

    async fn perform(
        &self,
        request: Request,
        _: Option<String>,
        credential: Option<GitUse>,
        exchange: &mut Exchange<Self>,
    ) -> Result<(), Failure> {
        let target = target_of(&request.url).map_err(Failure::Configuration)?;
        // Read as `target_of` read it, so a scheme written in capitals is ssh all the same.
        let over_ssh = Url::parse(&request.url).is_ok_and(|url| url.scheme() == "ssh");
        let ssh_key = credential
            .as_ref()
            .map(|c| matches!(c.0, Holding::SshKey(_)));
        match (over_ssh, ssh_key) {
            (true, None | Some(false)) => {
                return Err(Failure::Configuration(
                    "a repository over ssh is fetched only with an ssh key, whose binding pins its server's host key"
                        .to_string(),
                ));
            }
            (false, Some(true)) => {
                return Err(Failure::Configuration(
                    "an ssh key goes only over ssh".to_string(),
                ));
            }
            _ => {}
        }
        if !over_ssh {
            let login = match credential {
                Some(GitUse(Holding::Sent(login))) => Some(login),
                _ => None,
            };
            let through = https::Through::new(
                self.client.clone(),
                tokio::runtime::Handle::current(),
                target,
                login,
                self.max_fetch,
            );
            // gix blocks for as long as the fetch takes: on a thread of its own, it holds up no other request.
            let fetched = tokio::task::spawn_blocking(move || https::fetch(&request, through))
                .await
                .map_err(|joined| {
                    Failure::Transient(format!("the fetch did not finish: {joined}"))
                })??;
            exchange.reply(fetched).await;
            return Ok(());
        }
        let credential = match credential {
            Some(GitUse(Holding::SshKey(key))) => Some(key),
            _ => None,
        };
        // A proxy carries http only: where the way out is through one, ssh would go around it, so it does not go.
        if self
            .egress
            .proxy_for(&format!("https://{}/", target.host))
            .is_some()
        {
            return Err(Failure::Configuration(
                "the way out is through a proxy, which carries no ssh".to_string(),
            ));
        }
        let max_fetch = self.max_fetch;
        // libgit2 blocks for as long as the fetch takes: on a thread of its own, it holds up no other request.
        let fetched = tokio::task::spawn_blocking(move || {
            let told = Cell::new(None);
            let fetching = Fetching {
                credential: credential.as_ref(),
                host: &target.host,
                depth: request.depth,
                max_fetch,
                told: &told,
            };
            fetching
                .bring_up_to_date(&request)
                .map(|repository| Fetched { repository })
                .map_err(|e| {
                    told.take()
                        .unwrap_or_else(|| Failure::Transient(e.message().to_string()))
                })
        })
        .await
        .map_err(|joined| Failure::Transient(format!("the fetch did not finish: {joined}")))??;
        exchange.reply(fetched).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::judge::{Credential, Denial, Location, OperationDecl};
    use crate::protocol::testing::{GitOrigin, Site, git_ca, git_handle_for, handle_of};
    use crate::protocol::{Instances, Operation, ReadFailure};
    use polar::egress::testing::{
        TestCa, forwarding_proxy, given, https_server, recording_proxy, rerun,
    };
    use polar_crypto::registry::{SecretBinding, SecretKind};
    use proptest::prelude::*;

    const WITH_LOGIN: OperationDecl = OperationDecl {
        name: "test.fetch",
        doc: "",
        protocol: ProtocolKind::GIT,
        location: Location::Bound {
            credential: Credential::Chosen,
        },
    };
    const PUBLIC: OperationDecl = OperationDecl {
        name: "test.fetch-public",
        doc: "",
        protocol: ProtocolKind::GIT,
        location: Location::Arbitrary,
    };
    const DECLARED: &[OperationDecl] = &[WITH_LOGIN, PUBLIC];

    const TOKEN: &str = "a-token-that-is-nowhere-else";

    /// Reads the tip of the branch a clone tracks.
    struct Fetch<const CREDENTIAL: bool> {
        request: Request,
    }

    impl<const CREDENTIAL: bool> Operation for Fetch<CREDENTIAL> {
        type Protocol = Git;
        type Output = String;
        const DECL: OperationDecl = if CREDENTIAL { WITH_LOGIN } else { PUBLIC };

        fn request(&self) -> Request {
            self.request.clone()
        }
        fn credential(&self) -> Option<String> {
            CREDENTIAL.then(|| "gh".to_string())
        }
        fn read(&self, reply: &Fetched) -> Result<String, ReadFailure> {
            reply
                .repository
                .refname_to_id("refs/remotes/origin/main")
                .map(|oid| oid.to_string())
                .map_err(|e| ReadFailure::Malformed(e.message().to_string()))
        }
    }

    struct Rig {
        _origin_dir: tempfile::TempDir,
        repository: Repository,
        origin: GitOrigin,
        cache: tempfile::TempDir,
        tip: String,
    }

    fn commit(repository: &Repository, message: &str) -> String {
        let signature = git2::Signature::now("t", "t@example.org").unwrap();
        let tree = repository.treebuilder(None).unwrap().write().unwrap();
        let tree = repository.find_tree(tree).unwrap();
        let parent = repository
            .refname_to_id("refs/heads/main")
            .ok()
            .map(|oid| repository.find_commit(oid).unwrap());
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        repository
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                message,
                &tree,
                &parents,
            )
            .unwrap()
            .to_string()
    }

    async fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(dir.path()).unwrap();
        let tip = commit(&repository, "first");
        repository.set_head("refs/heads/main").unwrap();
        let origin = GitOrigin::serving(dir.path()).await;
        Rig {
            _origin_dir: dir,
            repository,
            origin,
            cache: tempfile::tempdir().unwrap(),
            tip,
        }
    }

    impl Rig {
        fn request(&self, url: &str) -> Request {
            Request::new(
                url,
                self.cache.path().join("clone"),
                vec!["origin".to_string()],
                None,
            )
        }
        fn cloned(&self) -> bool {
            self.cache.path().join("clone").exists()
        }
    }

    fn bound_to(host: &str) -> SecretBinding {
        SecretBinding {
            host_pattern: host.to_string(),
            kind: SecretKind::UserPassword,
            username: Some("svc".to_string()),
            host_key: None,
        }
    }

    /// The handler, with the one credential bound to `host`.
    async fn holding(host: &str) -> Site {
        git_handle_for(DECLARED, Some(("gh", TOKEN, bound_to(host)))).await
    }

    fn basic(username: &str, password: &str) -> Option<String> {
        use base64::Engine;
        let login =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        Some(format!("Basic {login}"))
    }

    fn files_holding(root: &Path, text: &[u8], found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_holding(&path, text, found);
            } else if std::fs::read(&path)
                .unwrap()
                .windows(text.len())
                .any(|window| window == text)
            {
                found.push(path);
            }
        }
    }

    // -- how an address reads ---------------------------------------------------------------------------------------

    #[test]
    fn an_address_is_read_for_its_host_and_whether_it_is_encrypted() {
        assert_eq!(
            target_of("https://GitHub.com:8443/o/r.git"),
            Ok(Target {
                host: "github.com".to_string(),
                encrypted: true,
                access: None,
                reaches_node: Vec::new(),
                namespace: None,
            })
        );
        assert_eq!(
            target_of("http://git.example.org/o/r.git"),
            Ok(Target {
                host: "git.example.org".to_string(),
                encrypted: false,
                access: None,
                reaches_node: Vec::new(),
                namespace: None,
            })
        );
    }

    #[test]
    fn an_address_that_could_be_read_two_ways_or_carries_a_login_goes_nowhere() {
        for address in [
            "https://u:p@github.com/o/r.git",
            "https://u@github.com/o/r.git",
            "https://github.com\\@evil.example.org/o/r.git",
            "https://github.com:/o/r.git",
            "https://github.com:x/o/r.git",
            "ssh://git@github.com/o/r.git",
            "git@github.com:o/r.git",
            "git://github.com/o/r.git",
            "file:///var/lib/r.git",
            "/var/lib/r.git",
            "not an address",
            "",
        ] {
            assert!(target_of(address).is_err(), "{address}");
        }
    }

    proptest! {
        /// What is allowed names one host: the text of its authority is that host and a port, whatever was written.
        #[test]
        fn what_is_taken_as_an_address_has_only_its_host_for_an_authority(
            scheme in "https?|ssh|git|file",
            authority in "[a-zA-Z0-9.:@\\\\%-]{0,24}",
            rest in "([/?#][a-z.]{0,8})?",
        ) {
            let address = format!("{scheme}://{authority}{rest}");
            if let Ok(target) = target_of(&address) {
                prop_assert!(!authority.contains('@') && !authority.contains('\\'));
                let name = authority.split(':').next().unwrap();
                prop_assert_eq!(name.to_ascii_lowercase(), target.host);
            }
        }
    }

    // -- a public repository ----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_public_repository_is_cloned_then_fetched_with_nothing_presented() {
        let r = rig().await;
        let site = holding("localhost").await;
        let url = r.origin.url();
        let first = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&url),
            })
            .await
            .unwrap();
        assert_eq!(first, r.tip);

        let second = commit(&r.repository, "second");
        let fetched = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&url),
            })
            .await
            .unwrap();
        assert_eq!(fetched, second, "the same clone, brought up to date");

        assert!(r.origin.presented().await.iter().all(Option::is_none));
        let records = site.records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            record.arbitrary
                && record.credential.is_none()
                && record.verdict == "allowed"
                && record.protocol == "git"
                && record.host == "127.0.0.1"
        }));
    }

    /// What the agents read of a clone: its refs and where they point, what `HEAD` names, and `origin`'s fetch refspec.
    fn shape(path: &Path) -> (Vec<(String, String)>, Option<String>, Vec<String>) {
        let repository = Repository::open_bare(path).unwrap();
        let mut refs: Vec<(String, String)> = repository
            .references()
            .unwrap()
            .map(|reference| {
                let reference = reference.unwrap();
                let points = match reference.symbolic_target() {
                    Some(target) => target.to_string(),
                    None => reference.target().unwrap().to_string(),
                };
                (reference.name().unwrap().to_string(), points)
            })
            .collect();
        refs.sort();
        let head = repository.find_reference("HEAD").unwrap();
        let refspecs: Vec<String> = repository
            .find_remote("origin")
            .unwrap()
            .fetch_refspecs()
            .unwrap()
            .iter()
            .flatten()
            .map(str::to_string)
            .collect();
        (refs, head.symbolic_target().map(str::to_string), refspecs)
    }

    /// What the agents read of a clone is as libgit2's clone made it: the same refs where they point, `HEAD` naming the
    /// remote's default branch, `refs/remotes/origin/HEAD` naming its tracking ref, and `origin`'s fetch refspec.
    #[tokio::test]
    async fn a_clone_over_https_is_the_clone_libgit2_made() {
        let r = rig().await;
        commit(&r.repository, "second");
        r.repository
            .reference(
                "refs/heads/feature",
                r.repository.refname_to_id("refs/heads/main").unwrap(),
                true,
                "",
            )
            .unwrap();
        let site = holding("localhost").await;
        site.handle
            .ask(Fetch::<false> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap();
        let by_libgit2 = tempfile::tempdir().unwrap();
        git2::build::RepoBuilder::new()
            .bare(true)
            .clone(&r.origin.url(), &by_libgit2.path().join("clone"))
            .unwrap();
        assert_eq!(
            shape(&r.cache.path().join("clone")),
            shape(&by_libgit2.path().join("clone"))
        );
    }

    /// Against git's own server, which speaks git's second protocol as GitHub's and gitea's do: a clone is libgit2's clone
    /// (its `HEAD` and `refs/remotes/origin/HEAD` among it, which that protocol lists only when asked), a fetch brings a
    /// new commit, and a depth of one is a shallow clone of the tip alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_real_git_server_is_cloned_fetched_and_cloned_shallow() {
        let root = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(root.path().join("r.git")).unwrap();
        commit(&repository, "first");
        repository.set_head("refs/heads/main").unwrap();
        let tip = repository.refname_to_id("refs/heads/main").unwrap();
        repository
            .reference("refs/heads/feature", tip, true, "")
            .unwrap();
        commit(&repository, "second");
        let origin = crate::protocol::testing::BackendOrigin::serving(root.path()).await;
        let site = holding("localhost").await;
        let cache = tempfile::tempdir().unwrap();
        let request = |at: &Path, depth| {
            Request::new(
                origin.url("r.git"),
                at.join("clone"),
                vec!["origin".to_string()],
                depth,
            )
        };

        let fetched = site
            .handle
            .ask(Fetch::<false> {
                request: request(cache.path(), None),
            })
            .await
            .unwrap();
        assert_eq!(
            fetched,
            repository
                .refname_to_id("refs/heads/main")
                .unwrap()
                .to_string()
        );
        let by_libgit2 = tempfile::tempdir().unwrap();
        git2::build::RepoBuilder::new()
            .bare(true)
            .clone(&origin.url("r.git"), &by_libgit2.path().join("clone"))
            .unwrap();
        let ours = shape(&cache.path().join("clone"));
        assert_eq!(ours, shape(&by_libgit2.path().join("clone")));
        assert!(ours.0.iter().any(
            |(name, to)| name == "refs/remotes/origin/HEAD" && to == "refs/remotes/origin/main"
        ));

        let third = commit(&repository, "third");
        let fetched = site
            .handle
            .ask(Fetch::<false> {
                request: request(cache.path(), None),
            })
            .await
            .unwrap();
        assert_eq!(fetched, third);

        let shallow = tempfile::tempdir().unwrap();
        site.handle
            .ask(Fetch::<false> {
                request: request(shallow.path(), Some(1)),
            })
            .await
            .unwrap();
        let clone = Repository::open_bare(shallow.path().join("clone")).unwrap();
        assert!(clone.is_shallow());
        let mut walk = clone.revwalk().unwrap();
        walk.push(clone.refname_to_id("refs/remotes/origin/main").unwrap())
            .unwrap();
        assert_eq!(walk.count(), 1);
    }

    /// A repository that moved within its host is followed there, and what git sends after its refs goes to where it went:
    /// the old address answers nothing but the move.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repository_moved_within_its_host_is_fetched_where_it_went() {
        let root = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(root.path().join("r.git")).unwrap();
        let tip = commit(&repository, "first");
        repository.set_head("refs/heads/main").unwrap();
        let origin = crate::protocol::testing::BackendOrigin::serving(root.path()).await;
        origin.moved("old.git", "r.git").await;
        let site = holding("localhost").await;
        let cache = tempfile::tempdir().unwrap();
        let fetched = site
            .handle
            .ask(Fetch::<false> {
                request: Request::new(
                    origin.url("old.git"),
                    cache.path().join("clone"),
                    vec!["origin".to_string()],
                    None,
                ),
            })
            .await
            .unwrap();
        assert_eq!(fetched, tip);
    }

    /// A fetch may bring exactly its bound, and not a byte more.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fetch_may_bring_its_bound_and_not_a_byte_more() {
        let r = rig().await;
        let git = Git::with_egress(Egress::default(), MAX_FETCH);
        let fetch = |max: usize, at: &str| {
            let request = r.request(&r.origin.url());
            let request = Request::new(&request.url, r.cache.path().join(at), Vec::new(), None);
            let through = https::Through::new(
                git.client.clone(),
                tokio::runtime::Handle::current(),
                target_of(&request.url).unwrap(),
                None,
                max,
            );
            let counted = through.clone();
            async move {
                let fetched = tokio::task::spawn_blocking(move || https::fetch(&request, through))
                    .await
                    .unwrap();
                (fetched.map(|_| ()), counted.received())
            }
        };
        let (whole, size) = fetch(MAX_FETCH, "whole").await;
        whole.unwrap();
        let (exact, _) = fetch(size, "exact").await;
        exact.unwrap();
        let (over, _) = fetch(size - 1, "over").await;
        let failure = over.unwrap_err();
        assert!(
            matches!(&failure, Failure::Transient(why) if why.contains(&format!("{} bytes", size - 1))),
            "{failure:?}"
        );
    }

    #[tokio::test]
    async fn a_repository_that_wants_a_login_of_a_request_with_none_fails_and_is_given_nothing() {
        let r = rig().await;
        r.origin.asks_for("svc", TOKEN);
        let site = holding("localhost").await;
        let failure = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Transient(why) if why.contains("names none")),
            "{failure:?}"
        );
        assert!(r.origin.presented().await.iter().all(Option::is_none));
        assert!(!r.cloned());
    }

    // -- a credential -----------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_credential_goes_to_the_host_it_is_bound_to_and_is_left_nowhere() {
        let r = rig().await;
        r.origin.asks_for("svc", TOKEN);
        let site = holding("localhost").await;
        let url = r.origin.url_over_tls().await;
        let tip = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap();
        assert_eq!(tip, r.tip);
        let presented = r.origin.presented().await;
        assert!(presented.contains(&basic("svc", TOKEN)), "{presented:?}");

        let second = commit(&r.repository, "second");
        let fetched = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap();
        assert_eq!(fetched, second);

        let mut found = Vec::new();
        files_holding(r.cache.path(), TOKEN.as_bytes(), &mut found);
        assert_eq!(found, Vec::<PathBuf>::new(), "the token is in the clone");
        let config = std::fs::read_to_string(r.cache.path().join("clone/config")).unwrap();
        assert!(config.contains(&url), "{config}");

        let records = site.records.lock().unwrap();
        assert!(records.iter().all(|record| {
            !record.arbitrary
                && record.credential.as_deref() == Some("gh")
                && record.host == "localhost"
        }));
    }

    #[tokio::test]
    async fn a_credential_is_not_presented_to_a_host_that_does_not_ask_for_it() {
        let r = rig().await;
        let site = holding("localhost").await;
        let url = r.origin.url_over_tls().await;
        site.handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap();
        assert!(r.origin.presented().await.iter().all(Option::is_none));
    }

    #[tokio::test]
    async fn a_refused_credential_is_presented_once_held_and_not_presented_again() {
        let r = rig().await;
        r.origin.asks_for("svc", "another-password");
        let site = holding("localhost").await;
        let url = r.origin.url_over_tls().await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(failure, Failure::CredentialRefused(_)),
            "{failure:?}"
        );
        let presented = r.origin.presented().await;
        assert_eq!(
            presented.iter().filter(|p| p.is_some()).count(),
            1,
            "{presented:?}"
        );

        let requests = presented.len();
        let held = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap_err();
        assert_eq!(
            held,
            Failure::CredentialHeld {
                name: "gh".to_string()
            }
        );
        assert_eq!(
            r.origin.presented().await.len(),
            requests,
            "nothing was sent"
        );
    }

    #[tokio::test]
    async fn a_credential_for_another_host_is_not_asked_of_the_host_at_all() {
        let r = rig().await;
        r.origin.asks_for("svc", TOKEN);
        let site = holding("github.com").await;
        let url = r.origin.url_over_tls().await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            Failure::NotBound {
                name: "gh".to_string()
            }
        );
        assert!(r.origin.presented().await.is_empty());
        assert!(!r.cloned());
    }

    #[tokio::test]
    async fn a_credential_goes_over_no_connection_that_is_not_encrypted() {
        let r = rig().await;
        r.origin.asks_for("svc", TOKEN);
        let site = holding("127.0.0.1").await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap_err();
        assert_eq!(failure, Failure::Denied(Denial::NotEncrypted));
        assert!(r.origin.presented().await.is_empty());
    }

    #[tokio::test]
    async fn a_credential_that_has_not_arrived_is_said_to_be_missing_and_nothing_is_sent() {
        let r = rig().await;
        let site = git_handle_for(DECLARED, Some(("another", TOKEN, bound_to("localhost")))).await;
        let url = r.origin.url_over_tls().await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            Failure::NoCredential {
                name: "gh".to_string()
            }
        );
        assert!(r.origin.presented().await.is_empty());
    }

    /// libgit2 connects where the clone's own remote says. What was judged is the request's address, so a remote that says
    /// another host gets nothing, whatever it asks.
    #[tokio::test]
    async fn a_clone_whose_remote_has_gone_elsewhere_is_not_given_the_credential() {
        let r = rig().await;
        let site = holding("localhost").await;
        site.handle
            .ask(Fetch::<false> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap();
        r.origin.asks_for("svc", TOKEN);
        let judged = r.origin.url_over_tls().await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&judged),
            })
            .await
            .unwrap_err();
        assert!(matches!(failure, Failure::Configuration(_)), "{failure:?}");
        assert!(r.origin.presented().await.iter().all(Option::is_none));
    }

    /// The stand-in cannot do a shallow fetch, and libgit2 finds that out only if it was asked for one.
    #[tokio::test]
    async fn the_depth_asked_for_reaches_git() {
        let r = rig().await;
        let site = holding("localhost").await;
        let request = Request::new(
            r.origin.url(),
            r.cache.path().join("clone"),
            vec!["origin".to_string()],
            Some(1),
        );
        let failure = site
            .handle
            .ask(Fetch::<false> { request })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Transient(why) if why.contains("shallow")),
            "{failure:?}"
        );
    }

    // -- redirects --------------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_redirect_to_another_host_takes_neither_the_credential_nor_the_request_there() {
        for first in [true, false] {
            let r = rig().await;
            r.origin.asks_for("svc", TOKEN);
            let elsewhere = rig().await;
            // Over TLS, as a redirect to plain http is refused for that alone. The certificate names both, and to the rules
            // `localhost`, where the request goes, and 127.0.0.1 are two hosts.
            let to = elsewhere
                .origin
                .url_over_tls()
                .await
                .replace("localhost", "127.0.0.1");
            if first {
                r.origin.redirects_first_to(to);
            } else {
                r.origin.redirects_to(to);
            }
            let site = holding("localhost").await;
            let url = r.origin.url_over_tls().await;
            let failure = site
                .handle
                .ask(Fetch::<true> {
                    request: r.request(&url),
                })
                .await
                .unwrap_err();
            assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
            assert_eq!(elsewhere.origin.presented().await, Vec::new());
            assert!(!r.cloned());
        }
    }

    #[tokio::test]
    async fn a_public_request_is_not_followed_to_another_host_either() {
        let r = rig().await;
        let elsewhere = rig().await;
        // The stand-ins are told apart by name: this one is at 127.0.0.1, and sends it to `localhost`.
        let to = elsewhere.origin.url().replace("127.0.0.1", "localhost");
        r.origin.redirects_first_to(to);
        let site = holding("localhost").await;
        let failure = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap_err();
        assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
        assert_eq!(elsewhere.origin.presented().await, Vec::new());
    }

    #[tokio::test]
    async fn a_redirect_within_the_host_is_followed() {
        let r = rig().await;
        let new_home = r.origin.url().replace("/r.git", "/new-home.git");
        r.origin.redirects_first_once_to(new_home);
        let site = holding("localhost").await;
        let tip = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap();
        assert_eq!(tip, r.tip);
        assert_eq!(
            r.origin.presented().await.len(),
            3,
            "the refs twice, and the pack"
        );
    }

    // -- bounds -----------------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn a_fetch_past_its_bound_fails_and_says_so() {
        let r = rig().await;
        let site = handle_of(
            Instances::of(Git::with_egress(Egress::default(), 16)),
            DECLARED,
            Vec::new(),
            None,
        )
        .await;
        let failure = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Transient(why) if why.contains("16 bytes")),
            "{failure:?}"
        );
        assert!(!r.cloned());
    }

    /// A host that takes the connection and says nothing holds only its own request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_that_says_nothing_holds_up_no_other_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = format!("http://{}/r.git", listener.local_addr().unwrap());
        let r = rig().await;
        let site = holding("localhost").await;

        let stuck_cache = tempfile::tempdir().unwrap();
        let handle = site.handle.clone();
        let request = Request::new(&silent, stuck_cache.path().join("clone"), Vec::new(), None);
        let stuck = tokio::spawn(async move { handle.ask(Fetch::<false> { request }).await });
        let (connection, _) = listener.accept().await.unwrap();

        let tip = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&r.origin.url()),
            })
            .await
            .unwrap();
        assert_eq!(tip, r.tip);
        assert!(!stuck.is_finished());
        drop(connection);
        drop(listener);
        assert!(stuck.await.unwrap().is_err());
    }

    // -- the egress probe -------------------------------------------------------------------------------------------

    /// The probe of `url` by git going out as `egress` says.
    async fn probe_of(url: &str, egress: Egress) -> Probed {
        git_ca();
        let proxied = egress.proxy_for(url).is_some();
        probe(
            Arc::new(Git::with_egress(egress, MAX_FETCH)),
            url.to_string(),
            proxied,
        )
        .await
    }

    /// A port nothing listens on.
    async fn closed_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_reaches_a_repository_and_presents_nothing_even_when_asked() {
        let r = rig().await;
        let url = r.origin.url_over_tls().await;
        let reached = probe_of(&url, Egress::default()).await;
        assert_eq!(reached.reach, Reach::Reached, "{reached:?}");
        r.origin.asks_for("svc", TOKEN);
        let asked = probe_of(&url, Egress::default()).await;
        assert_eq!(asked.reach, Reach::Reached, "{asked:?}");
        assert!(r.origin.presented().await.iter().all(Option::is_none));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_says_a_name_that_does_not_resolve_is_dns() {
        let probed = probe_of("https://nowhere.invalid/r.git", Egress::default()).await;
        assert_eq!(probed.reach, Reach::Dns, "{probed:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_says_a_port_that_refuses_is_unreachable() {
        let url = format!("https://127.0.0.1:{}/r.git", closed_port().await);
        let probed = probe_of(&url, Egress::default()).await;
        assert_eq!(probed.reach, Reach::Unreachable, "{probed:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_says_a_certificate_it_does_not_trust_is_tls() {
        let server = https_server(&TestCa::new("nobody trusts this")).await;
        let probed = probe_of(&format!("{}/r.git", server.url), Egress::default()).await;
        assert_eq!(probed.reach, Reach::Tls, "{probed:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_goes_through_the_proxy_as_the_agent_does() {
        let (proxy, seen) = forwarding_proxy().await;
        let r = rig().await;
        let url = r.origin.url_over_tls().await;
        let egress = Egress {
            proxy: Some(proxy),
            ..Egress::default()
        };
        let probed = probe_of(&url, egress).await;
        assert_eq!(probed.reach, Reach::Reached, "{probed:?}");
        let port = Url::parse(&url).unwrap().port().unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![format!("CONNECT localhost:{port} HTTP/1.1")]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_says_a_proxy_that_will_not_open_the_way_or_is_not_there_is_the_proxy() {
        let (refusing, _) = recording_proxy().await;
        let gone = format!("http://127.0.0.1:{}", closed_port().await);
        for proxy in [refusing, gone] {
            let egress = Egress {
                proxy: Some(proxy.clone()),
                ..Egress::default()
            };
            let probed = probe_of("https://outside.example.org/r.git", egress).await;
            assert_eq!(probed.reach, Reach::Proxy, "{proxy}: {probed:?}");
        }
    }

    #[tokio::test]
    async fn the_probe_does_not_go_over_ssh() {
        let probed = probe_of("ssh://git@example.org/r.git", Egress::default()).await;
        assert_eq!(probed.reach, Reach::Other, "{probed:?}");
    }

    // -- the way out ------------------------------------------------------------------------------------------------

    /// A repository outside the cluster goes through the proxy, as a CONNECT to its host; one the bypass list names does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repository_outside_goes_through_the_proxy_and_one_inside_does_not() {
        let (proxy, seen) = recording_proxy().await;
        let r = rig().await;
        let inside = r.origin.url_over_tls().await;
        let egress = Egress {
            proxy: Some(proxy),
            no_proxy: Some("localhost,127.0.0.1,::1,.svc,.cluster.local".to_string()),
            ca_cert: None,
            cluster_ca: None,
        };
        git_ca();
        let site = handle_of(
            Instances::of(Git::with_egress(egress, MAX_FETCH)),
            DECLARED,
            Vec::new(),
            None,
        )
        .await;
        let cache = tempfile::tempdir().unwrap();
        let outside = site
            .handle
            .ask(Fetch::<false> {
                request: Request::new(
                    "https://outside.example.org/r.git",
                    cache.path().join("outside"),
                    Vec::new(),
                    None,
                ),
            })
            .await;
        assert!(outside.is_err(), "the proxy refuses everything");
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["CONNECT outside.example.org:443 HTTP/1.1".to_string()]
        );

        let tip = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&inside),
            })
            .await
            .unwrap();
        assert_eq!(tip, r.tip);
        assert_eq!(seen.lock().unwrap().len(), 1, "the inside went through it");
    }

    /// In a child (EGRESS_TEST_URLS set): starts as an agent does, from POLAR_EGRESS_CA_CERT if it is set, then tries a clone
    /// of each URL.
    async fn clone_each() {
        let env: std::collections::HashMap<String, String> = given("POLAR_EGRESS_CA_CERT")
            .map(|ca| ("POLAR_EGRESS_CA_CERT".to_string(), ca))
            .into_iter()
            .collect();
        let config = polar_env::Config::builder(&env)
            .register(&polar::egress::SECTION)
            .build();
        let egress = Egress::read(&config).unwrap();
        let git = Git::ready(egress, CONNECT_TIMEOUT, SERVER_TIMEOUT)
            .await
            .unwrap();
        let urls = given("EGRESS_TEST_URLS").unwrap();
        for (i, url) in urls.split(',').enumerate() {
            let cache = tempfile::tempdir().unwrap();
            let request = Request::new(
                format!("{url}/r.git"),
                cache.path().join(i.to_string()),
                Vec::new(),
                None,
            );
            // What the clone found, for a person reading a failure: the stand-in is no git server.
            println!("CLONE {url} {}", clone_by(&git, request).await);
        }
    }

    /// A clone of `request`'s repository with no credential, by the client the child was given (EGRESS_TEST_CLIENT): gix,
    /// which fetches over https, or libgit2, whose CA and timeouts the probe and ssh still use. What went wrong, if anything.
    async fn clone_by(git: &Git, request: Request) -> String {
        if given("EGRESS_TEST_CLIENT").as_deref() == Some("libgit2") {
            let told = Cell::new(None);
            let fetching = Fetching {
                credential: None,
                host: "",
                depth: None,
                max_fetch: MAX_FETCH,
                told: &told,
            };
            return format!(
                "{:?}",
                fetching
                    .bring_up_to_date(&request)
                    .err()
                    .map(|e| e.message().to_string())
            );
        }
        let target = target_of(&request.url).unwrap();
        let through = https::Through::new(
            git.client.clone(),
            tokio::runtime::Handle::current(),
            target,
            None,
            MAX_FETCH,
        );
        let fetched = tokio::task::spawn_blocking(move || https::fetch(&request, through))
            .await
            .unwrap();
        format!("{:?}", fetched.err().map(|failure| failure.to_string()))
    }

    /// The egress CA is added to what libgit2 trusts, not put in place of the roots OpenSSL finds by default. Those are read
    /// from the process environment, so the clones are made in a child process: SSL_CERT_FILE, and NIX_SSL_CERT_FILE, which
    /// nixpkgs' OpenSSL reads in its place (OpenSSL's own default file otherwise; in the image, that is the system bundle).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_egress_ca_is_trusted_by_git_beside_the_image_roots() {
        if given("EGRESS_TEST_URLS").is_some() {
            return clone_each().await;
        }
        let dir = tempfile::tempdir().unwrap();
        let image = TestCa::new("image roots");
        let corporate = TestCa::new("corporate root");
        let image_file = image.write(dir.path(), "image.pem");
        let corporate_file = corporate.write(dir.path(), "corporate.pem");
        let name = "protocol::git::tests::the_egress_ca_is_trusted_by_git_beside_the_image_roots";

        for client in ["gix", "libgit2"] {
            // Without the egress CA only the image's server is trusted: the test can tell.
            let (inside, outside) = (https_server(&image).await, https_server(&corporate).await);
            let urls = format!("{},{}", inside.url, outside.url);
            let output = rerun(
                name,
                &[
                    ("SSL_CERT_FILE", image_file.to_str().unwrap()),
                    ("NIX_SSL_CERT_FILE", image_file.to_str().unwrap()),
                    ("EGRESS_TEST_URLS", &urls),
                    ("EGRESS_TEST_CLIENT", client),
                ],
            )
            .await;
            assert!(output.status.success(), "{client}: {output:?}");
            assert_eq!(
                (inside.served() > 0, outside.served() > 0),
                (true, false),
                "{client}: {}",
                String::from_utf8_lossy(&output.stdout)
            );

            let (inside, outside) = (https_server(&image).await, https_server(&corporate).await);
            let urls = format!("{},{}", inside.url, outside.url);
            let output = rerun(
                name,
                &[
                    ("SSL_CERT_FILE", image_file.to_str().unwrap()),
                    ("NIX_SSL_CERT_FILE", image_file.to_str().unwrap()),
                    ("POLAR_EGRESS_CA_CERT", corporate_file.to_str().unwrap()),
                    ("EGRESS_TEST_URLS", &urls),
                    ("EGRESS_TEST_CLIENT", client),
                ],
            )
            .await;
            assert!(output.status.success(), "{client}: {output:?}");
            assert_eq!(
                (inside.served() > 0, outside.served() > 0),
                (true, true),
                "{client}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }

    /// In a child (SILENT_HOST set): gives libgit2 a short bound, and clones from a host that takes the connection and says
    /// nothing.
    async fn clone_from_the_silent_host() {
        let git = Git::ready(
            Egress::default(),
            CONNECT_TIMEOUT,
            Duration::from_millis(300),
        )
        .await
        .unwrap();
        let cache = tempfile::tempdir().unwrap();
        let request = Request::new(
            given("SILENT_HOST").unwrap(),
            cache.path().join("clone"),
            Vec::new(),
            None,
        );
        let started = std::time::Instant::now();
        let failed = clone_by(&git, request).await;
        println!("GAVE UP after {:?}: {failed}", started.elapsed());
    }

    /// libgit2's timeout is global to the process, so this is a child's; gix's, its client's, is tested the same way. Without
    /// them the child would wait for as long as the host does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_that_stops_answering_fails_the_fetch_when_the_timeout_passes() {
        if given("SILENT_HOST").is_some() {
            return clone_from_the_silent_host().await;
        }
        for client in ["gix", "libgit2"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let silent = format!("http://{}/r.git", listener.local_addr().unwrap());
            let holding = tokio::spawn(async move {
                let mut held = Vec::new();
                while let Ok((connection, _)) = listener.accept().await {
                    held.push(connection);
                }
            });
            let output = tokio::time::timeout(
                Duration::from_secs(30),
                rerun(
                    "protocol::git::tests::a_host_that_stops_answering_fails_the_fetch_when_the_timeout_passes",
                    &[("SILENT_HOST", &silent), ("EGRESS_TEST_CLIENT", client)],
                ),
            )
            .await
            .expect("the child gave up in time");
            holding.abort();
            let said = String::from_utf8_lossy(&output.stdout);
            assert!(
                said.contains("GAVE UP") && said.contains("timed out"),
                "{client}: {said}"
            );
        }
    }

    /// The first thing a CA that cannot be used does is stop the agent, with the variable and the path.
    #[tokio::test]
    async fn a_ca_that_cannot_be_used_stops_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("empty.pem");
        std::fs::write(&file, "").unwrap();
        let egress = Egress {
            proxy: None,
            no_proxy: None,
            ca_cert: Some(file.to_str().unwrap().to_string()),
            cluster_ca: None,
        };
        let why = Git::ready(egress, CONNECT_TIMEOUT, SERVER_TIMEOUT)
            .await
            .err()
            .expect("it should refuse");
        assert!(why.contains("POLAR_EGRESS_CA_CERT"), "{why}");
    }

    // -- over ssh ---------------------------------------------------------------------------------------------------

    use crate::protocol::ssh_origin::{SshOrigin, fingerprint, key, openssh};
    use crate::protocol::testing::git_handle_through;

    #[test]
    fn an_ssh_address_is_read_for_its_host_and_is_encrypted_and_carries_no_login() {
        for (address, host) in [
            ("ssh://52.235.181.217/SEI/ACE.git", "52.235.181.217"),
            ("ssh://Git.Example.org:2222/o/r.git", "git.example.org"),
            ("SSH://git.example.org/o/r.git", "git.example.org"),
        ] {
            let target = target_of(address).unwrap();
            assert_eq!(
                (target.host.as_str(), target.encrypted),
                (host, true),
                "{address}"
            );
        }
        for address in [
            "ssh://git@52.235.181.217/SEI/ACE.git",
            "ssh://u:p@git.example.org/o/r.git",
            "ssh://git.example.org:/o/r.git",
            "ssh://git%2eexample.org/o/r.git",
            "ssh://[2001:db8::1]/o/r.git",
            "ssh:///o/r.git",
        ] {
            assert!(target_of(address).is_err(), "{address}");
        }
    }

    fn pinned(host: &str, pin: &str) -> SecretBinding {
        SecretBinding {
            host_pattern: host.to_string(),
            kind: SecretKind::SshKey,
            username: None,
            host_key: Some(pin.to_string()),
        }
    }

    /// The rig, its repository also served over ssh with the host key of `key(1)`, letting in `key(2)` as `git`.
    async fn over_ssh() -> (Rig, SshOrigin) {
        let r = rig().await;
        let origin =
            SshOrigin::serving(r._origin_dir.path(), key(1), key(2).public_key().clone()).await;
        (r, origin)
    }

    #[tokio::test]
    async fn a_repository_over_ssh_is_fetched_with_its_key_from_the_server_its_binding_pins_and_the_key_is_left_nowhere()
     {
        let (r, origin) = over_ssh().await;
        let secret = openssh(&key(2));
        let site = git_handle_for(
            DECLARED,
            Some(("gh", &secret, pinned("127.0.0.1", &fingerprint(&key(1))))),
        )
        .await;
        let tip = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&origin.url()),
            })
            .await
            .unwrap();
        assert_eq!(tip, r.tip);
        let second = commit(&r.repository, "second");
        let fetched = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&origin.url()),
            })
            .await
            .unwrap();
        assert_eq!(fetched, second, "the same clone, brought up to date");

        let seen = origin.seen();
        assert_eq!(seen.connections, 2);
        assert!(
            seen.offered
                .iter()
                .all(|offered| *offered == fingerprint(&key(2))),
            "{seen:?}"
        );
        assert!(
            seen.commands
                .iter()
                .all(|command| command.starts_with("git-upload-pack ")),
            "{seen:?}"
        );
        let mut found = Vec::new();
        files_holding(r.cache.path(), b"OPENSSH PRIVATE KEY", &mut found);
        assert_eq!(found, Vec::<PathBuf>::new(), "the key is in the clone");
        let records = site.records.lock().unwrap();
        assert!(records.iter().all(|record| {
            record.credential.as_deref() == Some("gh")
                && record.host == "127.0.0.1"
                && record.verdict == "allowed"
        }));
    }

    #[tokio::test]
    async fn a_server_showing_another_host_key_is_offered_nothing() {
        let (r, origin) = over_ssh().await;
        let secret = openssh(&key(2));
        let site = git_handle_for(
            DECLARED,
            Some(("gh", &secret, pinned("127.0.0.1", &fingerprint(&key(9))))),
        )
        .await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&origin.url()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Configuration(why) if why.contains("host key") && why.contains(&fingerprint(&key(1))) && why.contains("ssh-ed25519")),
            "{failure:?}"
        );
        let seen = origin.seen();
        assert_eq!(seen.connections, 1, "it connected, to see the host key");
        assert!(seen.offered.is_empty(), "a key was offered: {seen:?}");
        assert!(!r.cloned());
    }

    /// A binding pins each key the server has, since which it shows is negotiated: the one shown being among them is enough.
    #[tokio::test]
    async fn a_server_showing_any_one_of_the_keys_its_binding_pins_is_fetched_from() {
        let (r, origin) = over_ssh().await;
        let secret = openssh(&key(2));
        let pins = format!("{},{}", fingerprint(&key(9)), fingerprint(&key(1)));
        let site =
            git_handle_for(DECLARED, Some(("gh", &secret, pinned("127.0.0.1", &pins)))).await;
        let tip = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&origin.url()),
            })
            .await
            .unwrap();
        assert_eq!(tip, r.tip);
    }

    #[tokio::test]
    async fn a_repository_over_ssh_without_an_ssh_key_is_not_even_connected_to() {
        let (r, origin) = over_ssh().await;
        // No credential at all.
        let site = git_handle_for(DECLARED, None).await;
        let failure = site
            .handle
            .ask(Fetch::<false> {
                request: r.request(&origin.url()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Configuration(why) if why.contains("ssh key")),
            "{failure:?}"
        );
        // A token, which goes only to a host name, bound to the name the server is reached by.
        let site = git_handle_for(DECLARED, Some(("gh", TOKEN, bound_to("localhost")))).await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&origin.url_by_name()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Configuration(why) if why.contains("ssh key")),
            "{failure:?}"
        );
        assert_eq!(origin.seen().connections, 0);
        assert!(!r.cloned());
    }

    #[tokio::test]
    async fn an_ssh_key_never_goes_over_https() {
        let r = rig().await;
        r.origin.asks_for("git", "anything");
        let secret = openssh(&key(2));
        let site = git_handle_for(
            DECLARED,
            Some(("gh", &secret, pinned("localhost", &fingerprint(&key(1))))),
        )
        .await;
        let url = r.origin.url_over_tls().await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&url),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Configuration(why) if why.contains("only over ssh")),
            "{failure:?}"
        );
        assert!(
            r.origin.presented().await.is_empty(),
            "the origin was asked"
        );
    }

    #[tokio::test]
    async fn an_ssh_fetch_the_way_out_would_send_through_a_proxy_is_refused_not_sent_around_it() {
        let (r, origin) = over_ssh().await;
        let secret = openssh(&key(2));
        let egress = Egress {
            proxy: Some("http://127.0.0.1:9".to_string()),
            no_proxy: None,
            ca_cert: None,
            cluster_ca: None,
        };
        let site = git_handle_through(
            egress,
            DECLARED,
            Some(("gh", &secret, pinned("127.0.0.1", &fingerprint(&key(1))))),
        )
        .await;
        let failure = site
            .handle
            .ask(Fetch::<true> {
                request: r.request(&origin.url()),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&failure, Failure::Configuration(why) if why.contains("proxy")),
            "{failure:?}"
        );
        assert_eq!(origin.seen().connections, 0);
    }
}
