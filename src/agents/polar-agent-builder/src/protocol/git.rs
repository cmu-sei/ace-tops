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

//! The git protocol: a repository brought up to date in the agent's cache, and a callback that reads it. libgit2 does its
//! own I/O and asks for the credential through a callback, so that callback is here and nowhere else: it offers what the
//! CryptoActor gave for the host the request was judged for, once, and only over a connection to that host. libgit2 follows
//! a redirect within a host by itself and cannot ask about one to another, which would go unjudged and unrecorded, so it is
//! told to refuse those. libgit2's options are global to the process, so the CA and the timeouts are set once, here, when
//! the agent starts (docs/architecture/protocol-handlers.md, "The protocols").

use super::{
    CredentialSource, Exchange, Failure, Pending, Protocol, ProtocolKind, Started, Target,
};
use async_trait::async_trait;
use git2::{Cred, FetchOptions, ProxyOptions, RemoteCallbacks, RemoteRedirect, Repository};
use polar::egress::Egress;
use polar_crypto::CryptoError;
use polar_crypto::registry::GitCredential;
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
    let target = super::http::target_of(&url)?;
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

/// The git protocol, with the way out of the cluster.
pub struct Git {
    egress: Egress,
    max_fetch: usize,
}

impl Git {
    /// Gives libgit2 the egress CA and the timeouts, for the whole process.
    async fn ready(
        egress: Egress,
        connect_timeout: Duration,
        server_timeout: Duration,
    ) -> Result<Self, String> {
        if let Some(path) = &egress.ca_cert {
            let bundle = egress.ca_bundle().await.map_err(|e| e.to_string())?;
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
            egress,
            max_fetch: MAX_FETCH,
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn with_egress(egress: Egress, max_fetch: usize) -> Self {
        Self { egress, max_fetch }
    }
}

/// What a clone or a fetch is given, each time: the credential, the bound, the depth, and the proxy to go through, if any.
/// With none libgit2 connects directly: it is not told to look for one, so the process environment never decides.
struct Fetching<'a> {
    credential: Option<&'a GitCredential>,
    /// The host the request was judged for.
    host: &'a str,
    depth: Option<usize>,
    proxy: Option<&'a str>,
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
        callbacks.credentials(move |url, _, _| {
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
            // libgit2 asks again only when what it was given was refused, and would go on asking.
            if presented {
                told.set(Some(Failure::CredentialRefused(
                    "the repository's host asked again after it was presented".to_string(),
                )));
                return Err(git2::Error::from_str("refused"));
            }
            presented = true;
            let password = std::str::from_utf8(&credential.secret)
                .map_err(|_| git2::Error::from_str("the credential is not text"))?;
            Cred::userpass_plaintext(&credential.username, password)
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
        if let Some(proxy) = self.proxy {
            let mut through = ProxyOptions::new();
            through.url(proxy);
            options.proxy_options(through);
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

impl super::sealed::Sealed for Git {}

#[async_trait]
impl Protocol for Git {
    const KIND: ProtocolKind = ProtocolKind::GIT;
    const BUDGET: Duration = READ_BUDGET;
    type Request = Request;
    type Credential = GitCredential;
    type Reply = Fetched;

    fn configured_host(base: &str) -> Result<String, String> {
        target_of(base).map(|target| target.host)
    }

    fn target(request: &Request, _: Option<&str>) -> Result<Target, String> {
        target_of(&request.url)
    }

    async fn credential(
        source: &dyn CredentialSource,
        name: String,
        host: String,
    ) -> Result<GitCredential, CryptoError> {
        source.git(name, host).await
    }

    async fn perform(
        &self,
        request: Request,
        _: Option<String>,
        credential: Option<GitCredential>,
        exchange: &mut Exchange<Self>,
    ) -> Result<(), Failure> {
        let target = target_of(&request.url).map_err(Failure::Configuration)?;
        let proxy = self.egress.proxy_for(&request.url);
        let max_fetch = self.max_fetch;
        // libgit2 blocks for as long as the fetch takes: on a thread of its own, it holds up no other request.
        let fetched = tokio::task::spawn_blocking(move || {
            let told = Cell::new(None);
            let fetching = Fetching {
                credential: credential.as_ref(),
                host: &target.host,
                depth: request.depth,
                proxy: proxy.as_deref(),
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
    use polar::egress::testing::{TestCa, given, https_server, recording_proxy, rerun};
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
                encrypted: true
            })
        );
        assert_eq!(
            target_of("http://git.example.org/o/r.git"),
            Ok(Target {
                host: "git.example.org".to_string(),
                encrypted: false
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
        Git::ready(egress, CONNECT_TIMEOUT, SERVER_TIMEOUT)
            .await
            .unwrap();
        let urls = given("EGRESS_TEST_URLS").unwrap();
        for (i, url) in urls.split(',').enumerate() {
            let cache = tempfile::tempdir().unwrap();
            let told = Cell::new(None);
            let fetching = Fetching {
                credential: None,
                host: "",
                depth: None,
                proxy: None,
                max_fetch: MAX_FETCH,
                told: &told,
            };
            let request = Request::new(
                format!("{url}/r.git"),
                cache.path().join(i.to_string()),
                Vec::new(),
                None,
            );
            let result = fetching.bring_up_to_date(&request);
            // What the clone found, for a person reading a failure: the stand-in is no git server.
            println!(
                "CLONE {url} {:?}",
                result.err().map(|e| e.message().to_string())
            );
        }
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

        // Without the egress CA only the image's server is trusted: the test can tell.
        let (inside, outside) = (https_server(&image).await, https_server(&corporate).await);
        let urls = format!("{},{}", inside.url, outside.url);
        let output = rerun(
            name,
            &[
                ("SSL_CERT_FILE", image_file.to_str().unwrap()),
                ("NIX_SSL_CERT_FILE", image_file.to_str().unwrap()),
                ("EGRESS_TEST_URLS", &urls),
            ],
        )
        .await;
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            (inside.served() > 0, outside.served() > 0),
            (true, false),
            "{}",
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
            ],
        )
        .await;
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            (inside.served() > 0, outside.served() > 0),
            (true, true),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// In a child (SILENT_HOST set): gives libgit2 a short bound, and clones from a host that takes the connection and says
    /// nothing.
    async fn clone_from_the_silent_host() {
        Git::ready(
            Egress::default(),
            CONNECT_TIMEOUT,
            Duration::from_millis(300),
        )
        .await
        .unwrap();
        let cache = tempfile::tempdir().unwrap();
        let told = Cell::new(None);
        let fetching = Fetching {
            credential: None,
            host: "",
            depth: None,
            proxy: None,
            max_fetch: MAX_FETCH,
            told: &told,
        };
        let request = Request::new(
            given("SILENT_HOST").unwrap(),
            cache.path().join("clone"),
            Vec::new(),
            None,
        );
        let started = std::time::Instant::now();
        let failed = fetching.bring_up_to_date(&request).map(|_| ()).unwrap_err();
        println!(
            "GAVE UP after {:?}: {}",
            started.elapsed(),
            failed.message()
        );
    }

    /// The timeout is global to libgit2, so this is a child's. Without it the child would wait for as long as the host does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_that_stops_answering_fails_the_fetch_when_the_timeout_passes() {
        if given("SILENT_HOST").is_some() {
            return clone_from_the_silent_host().await;
        }
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
                &[("SILENT_HOST", &silent)],
            ),
        )
        .await
        .expect("the child gave up in time");
        holding.abort();
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(
            said.contains("GAVE UP") && said.contains("timed out"),
            "{said}"
        );
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
        };
        let why = Git::ready(egress, CONNECT_TIMEOUT, SERVER_TIMEOUT)
            .await
            .err()
            .expect("it should refuse");
        assert!(why.contains("POLAR_EGRESS_CA_CERT"), "{why}");
    }
}
