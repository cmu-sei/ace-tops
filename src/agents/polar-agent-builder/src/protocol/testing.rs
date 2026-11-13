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

//! A protocol handler for the tests of an agent: the real one, with the real client and the real judgment, given a test's
//! CA, variables and credentials. It holds only what the test gave it, so it is no way to a real credential.

use super::git::Git;
use super::http::Http;
use super::kubernetes::Kubernetes;
use super::{
    CredentialSource, CredentialsApplied, Holds, Instances, LiveConfiguration, Location,
    OperationDecl, ProtocolActor, ProtocolArgs, ProtocolHandle, ProtocolMessage, RequestRecord,
};
use crate::runtime::RuntimeValue;
use async_trait::async_trait;
use base64::Engine;
use git2::Repository;
use polar::egress::Egress;
use polar::egress::testing::TestCa;
use polar_crypto::registry::{
    GitCredential, HttpCredential, SecretBinding, SecretKind, UseRefusal,
};
use polar_crypto::sending::{self, HttpKind, SendError, Sent};
use polar_crypto::{CryptoError, Exchanged, TokenHandle};
use ractor::{Actor, ActorRef, OutputPort};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

/// A handler a test made, and what it recorded.
pub struct Site {
    pub handle: ProtocolHandle,
    pub records: Arc<Mutex<Vec<RequestRecord>>>,
    variables: Arc<Variables>,
}

impl Site {
    /// A signed update changes a variable.
    pub fn set(&self, name: &str, value: String) {
        self.variables
            .0
            .lock()
            .unwrap()
            .insert(name.to_string(), value);
    }
}

struct Variables(Mutex<HashMap<String, String>>);

#[async_trait]
impl LiveConfiguration for Variables {
    async fn value(&self, name: &str) -> Option<String> {
        self.0.lock().unwrap().get(name).cloned()
    }
    async fn section(&self, _: &str) -> Option<RuntimeValue> {
        None
    }
}

struct NoHealth;

impl Holds for NoHealth {
    fn hold_credentials(&self, _: String) {}
    fn release_credentials(&self) {}
}

/// Answers for one secret by the real rule (`polar_crypto::registry`).
struct OneSecret {
    name: String,
    secret: Vec<u8>,
    binding: SecretBinding,
}

/// Stands in for the CryptoActor in a test, from credentials the test holds in the clear: it answers as the actor does, and
/// [`CredentialSource`] comes with it, the HTTP side using what it answers as the actor would (a binding is checked against
/// where a request goes, a login's token kept and presented by its handle).
#[async_trait]
pub trait StandIn: Send + Sync {
    /// The credential `name` for `host`, or why not.
    async fn http(&self, name: String, host: String) -> Result<HttpCredential, CryptoError>;
    async fn git(&self, name: String, host: String) -> Result<GitCredential, CryptoError>;
    async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError>;
}

/// The tokens stand-ins were given for logins, by handle.
fn stand_in_tokens() -> &'static Mutex<HashMap<u64, polar_crypto::Zeroizing<Vec<u8>>>> {
    static TOKENS: OnceLock<Mutex<HashMap<u64, polar_crypto::Zeroizing<Vec<u8>>>>> =
        OnceLock::new();
    TOKENS.get_or_init(Mutex::default)
}

/// The credential `name` for where `request` goes.
async fn stand_in_credential<T: StandIn + ?Sized>(
    stand_in: &T,
    name: String,
    request: &reqwest::Request,
) -> Result<HttpCredential, CryptoError> {
    let host = request.url().host_str().unwrap_or_default().to_string();
    stand_in.http(name, host).await
}

#[async_trait]
impl<T: StandIn> CredentialSource for T {
    async fn http_kind(&self, name: String, host: String) -> Result<HttpKind, CryptoError> {
        self.http(name, host).await.map(|c| sending::kind_of(&c))
    }
    async fn send_http(
        &self,
        name: String,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<Sent, SendError> {
        let credential = stand_in_credential(self, name, &request).await?;
        sending::send(&credential, request, client).await
    }
    async fn exchange(
        &self,
        name: String,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<Exchanged, SendError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let credential = stand_in_credential(self, name, &request).await?;
        let answered = sending::log_in(&credential, request, client).await?;
        let token = answered.token.map(|token| {
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            stand_in_tokens().lock().unwrap().insert(id, token);
            TokenHandle::new(id, |id| {
                stand_in_tokens().lock().unwrap().remove(&id);
            })
        });
        Ok(Exchanged {
            status: answered.status,
            headers: answered.headers,
            token,
            kind: answered.kind,
            looks_base64: answered.looks_base64,
        })
    }
    async fn send_with_token(
        &self,
        token: &TokenHandle,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<reqwest::Response, SendError> {
        let held = stand_in_tokens().lock().unwrap().get(&token.id()).cloned();
        let held =
            held.ok_or_else(|| CryptoError::SecretNotRegistered(format!("token {}", token.id())))?;
        sending::send_bearer(&held, request, client).await
    }
    async fn git(&self, name: String, host: String) -> Result<GitCredential, CryptoError> {
        let credential = StandIn::git(self, name, host).await?;
        match credential.kind {
            SecretKind::SshKey => Ok(credential),
            _ => Err(CryptoError::Use(UseRefusal::SentNotGiven)),
        }
    }
    async fn git_kind(&self, name: String, host: String) -> Result<SecretKind, CryptoError> {
        StandIn::git(self, name, host).await.map(|c| c.kind)
    }
    async fn send_git(
        &self,
        name: String,
        request: reqwest::Request,
        client: reqwest::Client,
    ) -> Result<Sent, SendError> {
        let host = request.url().host_str().unwrap_or_default().to_string();
        let credential = StandIn::git(self, name, host).await?;
        if credential.kind == SecretKind::SshKey {
            return Err(CryptoError::Use(UseRefusal::NotForHttp).into());
        }
        let login = HttpCredential::Basic {
            username: credential.username.clone(),
            password: credential.secret.clone(),
        };
        sending::send(&login, request, client).await
    }
    async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError> {
        StandIn::bound_to(self, host).await
    }
}

#[async_trait]
impl StandIn for OneSecret {
    async fn http(&self, name: String, host: String) -> Result<HttpCredential, CryptoError> {
        if name != self.name {
            return Err(CryptoError::SecretNotRegistered(name));
        }
        polar_crypto::registry::http_credential(&self.binding, &self.secret, &host)
            .map_err(CryptoError::Use)
    }
    async fn git(&self, name: String, host: String) -> Result<GitCredential, CryptoError> {
        if name != self.name {
            return Err(CryptoError::SecretNotRegistered(name));
        }
        polar_crypto::registry::git_credential(&self.binding, &self.secret, &host)
            .map_err(CryptoError::Use)
    }
    async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError> {
        Ok(polar_crypto::registry::bound_to(
            [(self.name.as_str(), self.binding.host_pattern.as_str())],
            &host,
        )
        .map(str::to_string))
    }
}

/// A handler over HTTP that trusts `ca_pem` as well, with `operations` declared and `variables` in force, its credentials
/// answered by `credentials`.
pub async fn http_handle(
    ca_pem: &str,
    operations: &'static [OperationDecl],
    variables: Vec<(&str, String)>,
    credentials: Option<Arc<dyn CredentialSource>>,
) -> Site {
    let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("the test's CA");
    let client = Http::builder(super::http::CONNECT_TIMEOUT, super::http::REQUEST_TIMEOUT)
        .add_root_certificate(certificate)
        .no_proxy()
        .build()
        .expect("the test's client");
    handle_of(
        Instances::of(Http::with_client(client)),
        operations,
        variables,
        credentials,
    )
    .await
}

/// The handler a test made, over the protocol it started.
pub(crate) async fn handle_of(
    instances: Instances,
    operations: &'static [OperationDecl],
    variables: Vec<(&str, String)>,
    credentials: Option<Arc<dyn CredentialSource>>,
) -> Site {
    let records: Arc<Mutex<Vec<RequestRecord>>> = Arc::default();
    let recorded = records.clone();
    let applied: Arc<OutputPort<CredentialsApplied>> = Arc::new(OutputPort::default());
    let in_force = Arc::new(Mutex::new(None));
    let variables = Arc::new(Variables(Mutex::new(
        variables
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
    )));
    let (actor, _): (ActorRef<ProtocolMessage>, _) = Actor::spawn(
        None,
        ProtocolActor,
        ProtocolArgs {
            agent: "a-test".to_string(),
            declared: operations,
            instances,
            credentials,
            crypto: None,
            configuration: variables.clone(),
            health: Arc::new(NoHealth),
            record: Arc::new(move |record| recorded.lock().unwrap().push(record.clone())),
            // Each namespace key an operation names, as the namespace of the same name: a test's calls name it as declared.
            namespaces: operations
                .iter()
                .filter_map(|operation| match operation.location {
                    Location::Cluster {
                        namespace: Some(key),
                        ..
                    } => Some((key.to_string(), key.to_string())),
                    _ => None,
                })
                .collect(),
            applied: applied.clone(),
            in_force: in_force.clone(),
        },
    )
    .await
    .expect("the test's handler");
    Site {
        handle: ProtocolHandle {
            actor,
            applied,
            in_force,
        },
        records,
        variables,
    }
}

/// [`http_handle`] with one secret, answered by the real binding rule.
pub async fn http_handle_for(
    ca_pem: &str,
    operations: &'static [OperationDecl],
    variables: Vec<(&str, String)>,
    secret: Option<(&str, &str, SecretBinding)>,
) -> Site {
    http_handle(ca_pem, operations, variables, secret.map(one_secret)).await
}

/// [`git_handle`] with one secret, answered by the real binding rule.
pub async fn git_handle_for(
    operations: &'static [OperationDecl],
    secret: Option<(&str, &str, SecretBinding)>,
) -> Site {
    git_handle(operations, secret.map(one_secret)).await
}

fn one_secret((name, secret, binding): (&str, &str, SecretBinding)) -> Arc<dyn CredentialSource> {
    Arc::new(OneSecret {
        name: name.to_string(),
        secret: secret.as_bytes().to_vec(),
        binding,
    })
}

/// A handler over git, with `operations` declared and its credentials answered by `credentials`. It goes out directly, and
/// trusts the CA of [`git_ca`].
pub async fn git_handle(
    operations: &'static [OperationDecl],
    credentials: Option<Arc<dyn CredentialSource>>,
) -> Site {
    git_ca();
    handle_of(
        Instances::of(Git::with_egress(Egress::default(), super::git::MAX_FETCH)),
        operations,
        Vec::new(),
        credentials,
    )
    .await
}

/// A handler over git as [`git_handle_for`] makes one, going out the way `egress` says.
#[cfg(test)]
pub(crate) async fn git_handle_through(
    egress: Egress,
    operations: &'static [OperationDecl],
    secret: Option<(&str, &str, SecretBinding)>,
) -> Site {
    git_ca();
    handle_of(
        Instances::of(Git::with_egress(egress, super::git::MAX_FETCH)),
        operations,
        Vec::new(),
        secret.map(one_secret),
    )
    .await
}

/// A handler over git and HTTP at once, as an agent that fetches a repository and pushes what it made of it has: git going
/// out directly and trusting the CA of [`git_ca`], HTTP trusting `ca_pem` as well, `operations` declared and `variables` in
/// force, its credentials answered by `credentials`.
pub async fn git_and_http_handle(
    ca_pem: &str,
    operations: &'static [OperationDecl],
    variables: Vec<(&str, String)>,
    credentials: Option<Arc<dyn CredentialSource>>,
) -> Site {
    git_ca();
    let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("the test's CA");
    let client = Http::builder(super::http::CONNECT_TIMEOUT, super::http::REQUEST_TIMEOUT)
        .add_root_certificate(certificate)
        .no_proxy()
        .build()
        .expect("the test's client");
    handle_of(
        Instances::of(Git::with_egress(Egress::default(), super::git::MAX_FETCH))
            .and(Http::with_client(client)),
        operations,
        variables,
        credentials,
    )
    .await
}

/// The CA a git server of a test presents a certificate from. libgit2 takes a CA once, for the whole process, so all the
/// tests of a process share this one.
pub fn git_ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(|| {
        let ca = TestCa::new("git tests");
        let dir = std::env::temp_dir().join(format!("polar-git-test-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a directory for the test's CA");
        let file = ca.write(&dir, "ca.pem");
        super::git::trust_ca_file(&file).expect("libgit2 takes the test's CA");
        let _ = std::fs::remove_dir_all(&dir);
        ca
    })
}

/// A handler over the Kubernetes API of `api`, over TLS, with `operations` declared.
pub async fn kubernetes_handle(operations: &'static [OperationDecl], api: &KubeApi) -> Site {
    let port = polar::egress::testing::https_front(&api.ca, &api.server.uri()).await;
    let mut config = api.config(&format!("https://localhost:{port}"));
    let der = base64::engine::general_purpose::STANDARD.decode(
        api.ca
            .pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>(),
    );
    config.root_cert = Some(vec![der.expect("the test's CA")]);
    let _ = rustls::crypto::ring::default_provider().install_default();
    kubernetes_of(operations, config).await
}

/// [`kubernetes_handle`] with no TLS at all.
pub async fn kubernetes_handle_unencrypted(
    operations: &'static [OperationDecl],
    api: &KubeApi,
) -> Site {
    let _ = rustls::crypto::ring::default_provider().install_default();
    kubernetes_of(operations, api.config(&api.server.uri())).await
}

async fn kubernetes_of(operations: &'static [OperationDecl], config: kube::Config) -> Site {
    let kubernetes = Kubernetes::of(config).expect("the test's client");
    handle_of(Instances::of(kubernetes), operations, Vec::new(), None).await
}

/// A stand-in Kubernetes API, as much as `kube`'s watcher needs: a list of what a path holds, then what a watch is to say,
/// and after that a watch that stays open saying nothing, as a real one does between changes.
pub struct KubeApi {
    server: MockServer,
    ca: TestCa,
    state: Arc<ApiState>,
    token_file: PathBuf,
}

/// What a method and a path are answered, the next first: a status and a body.
type Answers = std::collections::VecDeque<(u16, serde_json::Value)>;

#[derive(Default)]
struct ApiState {
    paths: Mutex<HashMap<String, ApiPath>>,
    /// What a request of a method and a path is answered, the next first: a status and a body.
    answers: Mutex<HashMap<(String, String), Answers>>,
    /// A pod's log, by the path it is read at.
    logs: Mutex<HashMap<String, Vec<u8>>>,
}

#[derive(Default)]
struct ApiPath {
    items: Vec<serde_json::Value>,
    list_refused: Option<u16>,
    /// What each watch is to say, the next first.
    watches: std::collections::VecDeque<WatchAnswer>,
}

enum WatchAnswer {
    Lines(String),
    Status(u16),
}

impl KubeApi {
    /// The token its client presents, from its file.
    pub const TOKEN: &'static str = "the-pods-own-token";
    pub const BEARER: &'static str = "Bearer the-pods-own-token";

    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(ApiState::default());
        Mock::given(any())
            .respond_with(ApiResponder(state.clone()))
            .mount(&server)
            .await;
        let token_file = std::env::temp_dir().join(format!(
            "polar-kube-test-token-{}-{}",
            std::process::id(),
            server.address().port()
        ));
        std::fs::write(&token_file, Self::TOKEN).expect("the test's token");
        Self {
            server,
            ca: TestCa::new("kube tests"),
            state,
            token_file,
        }
    }

    fn config(&self, address: &str) -> kube::Config {
        let mut config = kube::Config::new(address.parse().expect("the test's address"));
        config.auth_info.token_file = Some(self.token_file.display().to_string());
        config
    }

    /// A list of `path` gives these, without the `apiVersion` and `kind` that a list's items do not carry.
    pub fn holds(&self, path: &str, items: Vec<serde_json::Value>) {
        self.state
            .paths
            .lock()
            .unwrap()
            .entry(path.to_string())
            .or_default()
            .items = items;
    }

    /// A list of `path` is refused with this status.
    pub fn refuses_the_list(&self, path: &str, status: u16) {
        self.state
            .paths
            .lock()
            .unwrap()
            .entry(path.to_string())
            .or_default()
            .list_refused = Some(status);
    }

    /// The next watch of `path` says these, each a type, a name and a resource version, and ends as a real one does when
    /// its time is up.
    pub fn then_says(&self, path: &str, events: Vec<(&str, &str, &str)>) {
        let lines: String = events
            .into_iter()
            .map(|(kind, name, version)| {
                let object = serde_json::json!({
                    "apiVersion": "v1", "kind": "Whatever",
                    "metadata": {"name": name, "resourceVersion": version},
                });
                format!("{}\n", serde_json::json!({"type": kind, "object": object}))
            })
            .collect();
        self.then(path, WatchAnswer::Lines(lines));
    }

    /// The next watch of `path` is refused with this status.
    pub fn then_fails(&self, path: &str, status: u16) {
        self.then(path, WatchAnswer::Status(status));
    }

    /// The next watch of `path` is accepted, and says this status in its stream.
    pub fn then_errs(&self, path: &str, status: u16) {
        let line = serde_json::json!({"type": "ERROR", "object": api_status(status)});
        self.then(path, WatchAnswer::Lines(format!("{line}\n")));
    }

    fn then(&self, path: &str, answer: WatchAnswer) {
        self.state
            .paths
            .lock()
            .unwrap()
            .entry(path.to_string())
            .or_default()
            .watches
            .push_back(answer);
    }

    /// What each request presented, in order: its `Authorization`, or nothing.
    pub async fn presented(&self) -> Vec<Option<String>> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|request| {
                request
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            })
            .collect()
    }

    /// How many requests have been made of `path`.
    pub async fn asked_of(&self, path: &str) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path() == path)
            .count()
    }

    /// The next `method` request of `path` is answered with this status and body (as JSON).
    pub fn answers(&self, method: &str, path: &str, status: u16, body: serde_json::Value) {
        self.state
            .answers
            .lock()
            .unwrap()
            .entry((method.to_string(), path.to_string()))
            .or_default()
            .push_back((status, body));
    }

    /// A read of the log at `path` gives these bytes, and then ends.
    pub fn logs(&self, path: &str, body: Vec<u8>) {
        self.state
            .logs
            .lock()
            .unwrap()
            .insert(path.to_string(), body);
    }

    /// Each request, in order: its method, path, query and body.
    pub async fn received(&self) -> Vec<(String, String, String, Vec<u8>)> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|request| {
                (
                    request.method.to_string(),
                    request.url.path().to_string(),
                    request.url.query().unwrap_or_default().to_string(),
                    request.body.clone(),
                )
            })
            .collect()
    }

    /// Each request's query, in order.
    pub async fn queries(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|request| request.url.query().unwrap_or_default().to_string())
            .collect()
    }
}

impl Drop for KubeApi {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.token_file);
    }
}

fn api_status(code: u16) -> serde_json::Value {
    serde_json::json!({
        "kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure",
        "message": "the stand-in said so", "reason": "Whatever", "code": code,
    })
}

struct ApiResponder(Arc<ApiState>);

impl Respond for ApiResponder {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let asked = (request.method.to_string(), request.url.path().to_string());
        if let Some((status, body)) = self
            .0
            .answers
            .lock()
            .unwrap()
            .get_mut(&asked)
            .and_then(|answers| answers.pop_front())
        {
            return ResponseTemplate::new(status).set_body_json(body);
        }
        if let Some(log) = self.0.logs.lock().unwrap().get(request.url.path()) {
            return ResponseTemplate::new(200).set_body_bytes(log.clone());
        }
        let mut paths = self.0.paths.lock().unwrap();
        let Some(path) = paths.get_mut(request.url.path()) else {
            return ResponseTemplate::new(404).set_body_json(api_status(404));
        };
        let watching = request
            .url
            .query()
            .unwrap_or_default()
            .contains("watch=true");
        if !watching {
            if let Some(status) = path.list_refused {
                return ResponseTemplate::new(status).set_body_json(api_status(status));
            }
            return ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "List",
                "metadata": {"resourceVersion": "100"},
                "items": path.items,
            }));
        }
        match path.watches.pop_front() {
            Some(WatchAnswer::Lines(lines)) => ResponseTemplate::new(200).set_body_string(lines),
            Some(WatchAnswer::Status(status)) => {
                ResponseTemplate::new(status).set_body_json(api_status(status))
            }
            // Nothing to say: it stays open, for longer than any test.
            None => ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(600)),
        }
    }
}

/// A stand-in git server: the smart protocol, as little of it as libgit2 needs, over the repository in a directory as it
/// is at each request. It can ask for a login, and send a request elsewhere. A directory that has gone is a 503.
pub struct GitOrigin {
    server: MockServer,
    state: Arc<OriginState>,
}

struct OriginState {
    directory: PathBuf,
    /// The login it asks for, as what a Basic header holds.
    login: Mutex<Option<String>>,
    /// Where it sends a request for the refs to, and whether only after the login.
    redirect: Mutex<Option<(String, bool)>>,
    /// Where it sends the first request for the refs to.
    redirect_once: Mutex<Option<String>>,
}

impl GitOrigin {
    /// Serves the repository in `directory`, to anyone.
    pub async fn serving(directory: &Path) -> Self {
        let state = Arc::new(OriginState {
            directory: directory.to_path_buf(),
            login: Mutex::new(None),
            redirect: Mutex::new(None),
            redirect_once: Mutex::new(None),
        });
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(OriginResponder(state.clone()))
            .mount(&server)
            .await;
        Self { server, state }
    }

    /// From now on, only to this user and password.
    pub fn asks_for(&self, username: &str, password: &str) {
        let login =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        *self.state.login.lock().unwrap() = Some(login);
    }

    /// From now on a request for the refs is sent to `address`, a repository's, once any login has been given.
    pub fn redirects_to(&self, address: String) {
        *self.state.redirect.lock().unwrap() = Some((address, true));
    }

    /// From now on a request for the refs is sent to `address` before anything is asked of it.
    pub fn redirects_first_to(&self, address: String) {
        *self.state.redirect.lock().unwrap() = Some((address, false));
    }

    /// A request for the refs at any other address is sent to `address`, this server's own, which is taken as this repository.
    pub fn redirects_first_once_to(&self, address: String) {
        *self.state.redirect_once.lock().unwrap() = Some(address);
    }

    /// The address of the repository, unencrypted.
    pub fn url(&self) -> String {
        format!("{}/r.git", self.server.uri())
    }

    /// The address of the repository at `host` over TLS, under a certificate of [`git_ca`].
    pub async fn url_over_tls(&self) -> String {
        let port = polar::egress::testing::https_front(git_ca(), &self.server.uri()).await;
        format!("https://localhost:{port}/r.git")
    }

    /// What each request presented, in order: its `Authorization`, or nothing.
    pub async fn presented(&self) -> Vec<Option<String>> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|request| {
                request
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            })
            .collect()
    }
}

struct OriginResponder(Arc<OriginState>);

impl Respond for OriginResponder {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        let presented = request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        let refs = request.method == wiremock::http::Method::GET;
        let redirect = self.0.redirect.lock().unwrap().clone();
        if let Some((to, false)) = &redirect
            && refs
        {
            return moved_to(to);
        }
        if refs && let Some(to) = self.0.redirect_once.lock().unwrap().take() {
            return moved_to(&to);
        }
        let login = self.0.login.lock().unwrap().clone();
        if let Some(login) = login
            && presented != Some(format!("Basic {login}").as_str())
        {
            return ResponseTemplate::new(401)
                .insert_header("WWW-Authenticate", "Basic realm=\"git\"");
        }
        if let Some((to, true)) = &redirect
            && refs
        {
            return moved_to(to);
        }
        let Ok(repository) = Repository::open(&self.0.directory) else {
            return ResponseTemplate::new(503);
        };
        match refs {
            true => ResponseTemplate::new(200).set_body_raw(
                advertisement(&repository).expect("the origin's refs"),
                "application/x-git-upload-pack-advertisement",
            ),
            // A round of the negotiation that is not the last is answered that nothing is in common yet; the last, with
            // everything.
            false if !request.body.windows(9).any(|w| w == b"0009done\n") => {
                ResponseTemplate::new(200).set_body_raw(
                    pkt("NAK\n").into_bytes(),
                    "application/x-git-upload-pack-result",
                )
            }
            false => ResponseTemplate::new(200).set_body_raw(
                pack_reply(&repository, asked_for_side_band(&request.body))
                    .expect("the origin's pack"),
                "application/x-git-upload-pack-result",
            ),
        }
    }
}

fn moved_to(address: &str) -> ResponseTemplate {
    ResponseTemplate::new(302).insert_header(
        "Location",
        format!("{address}/info/refs?service=git-upload-pack"),
    )
}

/// A line of the protocol.
fn pkt(line: &str) -> String {
    format!("{:04x}{line}", line.len() + 4)
}

/// The refs of `repository`, as a server first says them over HTTP: the service named, then the refs.
fn advertisement(repository: &Repository) -> Result<Vec<u8>, git2::Error> {
    let mut said = format!("{}0000", pkt("# service=git-upload-pack\n")).into_bytes();
    said.extend(refs_advertised(repository)?);
    Ok(said)
}

/// The refs of `repository`, as `git-upload-pack` first says them (over ssh, this is all it says before the client asks).
/// It offers none of the protocol's capabilities it can do without, so what follows is a plain pack.
pub(crate) fn refs_advertised(repository: &Repository) -> Result<Vec<u8>, git2::Error> {
    let mut refs = Vec::new();
    for reference in repository.references()? {
        let reference = reference?;
        if let (Some(name), Some(target)) = (reference.name(), reference.target()) {
            refs.push((name.to_string(), target));
        }
    }
    refs.sort();
    let head = repository
        .head()
        .ok()
        .and_then(|head| Some((head.name()?.to_string(), head.target()?)));
    // multi_ack_detailed, side-band-64k and include-tag are the least a client asks of a server (gix fetches with no less),
    // and every server has them.
    let capabilities = match &head {
        Some((name, _)) => {
            format!("multi_ack_detailed side-band-64k include-tag symref=HEAD:{name}")
        }
        None => "multi_ack_detailed side-band-64k include-tag".to_string(),
    };
    let mut lines = Vec::new();
    let mut listed = Vec::new();
    if let Some((_, target)) = &head {
        listed.push((*target, "HEAD".to_string()));
    }
    listed.extend(refs.into_iter().map(|(name, target)| (target, name)));
    match listed.split_first() {
        Some(((target, name), rest)) => {
            lines.push(pkt(&format!("{target} {name}\0{capabilities}\n")));
            lines.extend(
                rest.iter()
                    .map(|(target, name)| pkt(&format!("{target} {name}\n"))),
            );
        }
        None => lines.push(pkt(&format!(
            "{} capabilities^{{}}\0{capabilities}\n",
            git2::Oid::zero()
        ))),
    }
    lines.push("0000".to_string());
    Ok(lines.concat().into_bytes())
}

/// Whether a client's first `want` asked for the pack in side bands.
pub(crate) fn asked_for_side_band(asked: &[u8]) -> bool {
    asked
        .split(|&b| b == b'\n')
        .find(|line| line.windows(4).any(|w| w == b"want"))
        .is_some_and(|line| line.windows(13).any(|w| w == b"side-band-64k"))
}

/// All of `repository`, whatever was asked for: a client takes what it already has without harm.
pub(crate) fn pack_reply(repository: &Repository, side_band: bool) -> Result<Vec<u8>, git2::Error> {
    let mut walk = repository.revwalk()?;
    for reference in repository.references()? {
        if let Some(target) = reference?.target() {
            walk.push(target)?;
        }
    }
    let mut builder = repository.packbuilder()?;
    builder.insert_walk(&mut walk)?;
    let mut pack = git2::Buf::new();
    builder.write_buf(&mut pack)?;
    let mut reply = pkt("NAK\n").into_bytes();
    if !side_band {
        reply.extend_from_slice(&pack);
        return Ok(reply);
    }
    // In band 1, a line at a time, and a flush at the end.
    for piece in pack.chunks(65515) {
        reply.extend_from_slice(format!("{:04x}", piece.len() + 5).as_bytes());
        reply.push(1);
        reply.extend_from_slice(piece);
    }
    reply.extend_from_slice(b"0000");
    Ok(reply)
}

/// A real git server for the tests: git's own `http-backend`, run for each request as a web server runs it, serving the
/// repositories under a directory. It speaks every protocol git does, the second among them, as GitHub's and gitea's
/// servers do: what [`GitOrigin`], which speaks only the first, cannot show.
#[cfg(test)]
pub(crate) struct BackendOrigin {
    server: MockServer,
}

#[cfg(test)]
impl BackendOrigin {
    /// Serves each repository under `root`, `root/<name>` at `/<name>`.
    pub(crate) async fn serving(root: &Path) -> Self {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(Backend(root.to_path_buf()))
            .mount(&server)
            .await;
        Self { server }
    }

    /// The address of the repository `name`, unencrypted.
    pub(crate) fn url(&self, name: &str) -> String {
        format!("{}/{name}", self.server.uri())
    }
    /// From now on `from` has moved to `to`: a request for its refs is sent there, and anything else asked of it is not
    /// found, so only a client that follows the move to the end gets anything.
    pub(crate) async fn moved(&self, from: &str, to: &str) {
        Mock::given(wiremock::matchers::path_regex(format!("^/{from}/")))
            .respond_with(Moved {
                from: from.to_string(),
                to: to.to_string(),
            })
            .with_priority(1)
            .mount(&self.server)
            .await;
    }
}

#[cfg(test)]
struct Moved {
    from: String,
    to: String,
}

#[cfg(test)]
impl Respond for Moved {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        if request.method != wiremock::http::Method::GET {
            return ResponseTemplate::new(404);
        }
        let path =
            request
                .url
                .path()
                .replacen(&format!("/{}/", self.from), &format!("/{}/", self.to), 1);
        let query = request
            .url
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        ResponseTemplate::new(301).insert_header("Location", format!("{path}{query}"))
    }
}

#[cfg(test)]
struct Backend(PathBuf);

#[cfg(test)]
impl Respond for Backend {
    fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
        use std::io::Write;
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let mut child = std::process::Command::new("git")
            .arg("http-backend")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_PROJECT_ROOT", &self.0)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REQUEST_METHOD", request.method.as_str())
            .env("PATH_INFO", request.url.path())
            .env("QUERY_STRING", request.url.query().unwrap_or_default())
            .env("CONTENT_TYPE", header("content-type"))
            .env("GIT_PROTOCOL", header("git-protocol"))
            .env("REMOTE_ADDR", "127.0.0.1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("git http-backend");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&request.body)
            .unwrap();
        let output = child.wait_with_output().unwrap();
        // A CGI reply: its headers, a blank line, its body.
        let split = output
            .stdout
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|at| (at, at + 4))
            .or_else(|| {
                output
                    .stdout
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .map(|at| (at, at + 2))
            })
            .expect("a CGI reply");
        let head = String::from_utf8_lossy(&output.stdout[..split.0]).to_string();
        let body = output.stdout[split.1..].to_vec();
        let mut status = 200;
        let mut content_type = "application/octet-stream".to_string();
        for line in head.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            match name.trim().to_ascii_lowercase().as_str() {
                "status" => {
                    status = value.trim()[..3].parse().unwrap();
                }
                "content-type" => content_type = value.trim().to_string(),
                _ => {}
            }
        }
        ResponseTemplate::new(status).set_body_raw(body, &content_type)
    }
}
