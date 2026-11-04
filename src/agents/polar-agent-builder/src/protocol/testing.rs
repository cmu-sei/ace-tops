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
use super::{
    CredentialSource, CredentialsApplied, Holds, Instances, LiveConfiguration, OperationDecl,
    ProtocolActor, ProtocolArgs, ProtocolHandle, ProtocolMessage, RequestRecord,
};
use crate::runtime::RuntimeValue;
use async_trait::async_trait;
use base64::Engine;
use git2::Repository;
use polar::egress::Egress;
use polar::egress::testing::TestCa;
use polar_crypto::CryptoError;
use polar_crypto::registry::{GitCredential, HttpCredential, SecretBinding};
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

#[async_trait]
impl CredentialSource for OneSecret {
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
            false => ResponseTemplate::new(200).set_body_raw(
                pack_reply(&repository).expect("the origin's pack"),
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

/// The refs of `repository`, as a server first says them. It offers none of the protocol's capabilities it can do without,
/// so what follows is a plain pack.
fn advertisement(repository: &Repository) -> Result<Vec<u8>, git2::Error> {
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
    let capabilities = match &head {
        Some((name, _)) => format!("symref=HEAD:{name}"),
        None => String::new(),
    };
    let mut lines = vec![pkt("# service=git-upload-pack\n"), "0000".to_string()];
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
        None => lines.push(pkt(&format!("{} capabilities^{{}}\0\n", git2::Oid::zero()))),
    }
    lines.push("0000".to_string());
    Ok(lines.concat().into_bytes())
}

/// All of `repository`, whatever was asked for: a client takes what it already has without harm.
fn pack_reply(repository: &Repository) -> Result<Vec<u8>, git2::Error> {
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
    reply.extend_from_slice(&pack);
    Ok(reply)
}
