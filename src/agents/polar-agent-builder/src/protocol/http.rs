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

//! The HTTP protocol: one request, and one whole, bounded reply. It goes out as the cluster says (`polar::egress`), and
//! presents the credential itself. It follows a redirect only after judging where it goes, so a credential goes to no host
//! it is not bound to, and it makes one attempt: a failure is the domain's to act on, and a host's `Retry-After` is the
//! handler's to honour (docs/architecture/protocol-handlers.md). A container registry is this protocol with one more way
//! of authenticating ([`Request::at_a_registry`]): the login goes only where a judged challenge sends it, and what comes
//! back goes only to the registry.

use super::{
    CredentialSource, Exchange, Failure, Pending, Protocol, ProtocolKind, Started, Target,
};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use polar_crypto::CryptoError;
use polar_crypto::Zeroizing;
use polar_crypto::registry::HttpCredential;
use reqwest::header::{LOCATION, RETRY_AFTER, WWW_AUTHENTICATE};
use reqwest::redirect::Policy;
use reqwest::{Client, ClientBuilder, Method, Url};
use std::sync::Arc;
use std::time::Duration;

pub use reqwest::StatusCode;
pub use reqwest::header::HeaderMap;

/// How long opening a connection may take, the TLS handshake included. A host that has not answered by then is as good
/// as unreachable.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one request may take, from sending it to the end of its body: without a bound, a host that stops answering
/// in the middle of one leaves the request waiting for ever.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// The most a reply may hold. A reply is whole in memory for `read`, so this is what one host can cost this agent.
pub const MAX_BODY: usize = 256 * 1024 * 1024;
/// The most hops a request follows, as a browser would.
pub const MAX_HOPS: usize = 10;
/// The most a registry's auth host may answer with: a token, and what comes with it.
pub const MAX_TOKEN_REPLY: usize = 1024 * 1024;

/// What an operation says it wants. Where it goes is a path under the operation's configured address, or a whole address
/// for an operation that learns its host at run time.
#[derive(Debug, Clone)]
pub struct Request {
    method: Method,
    at: At,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    /// For a request at a container registry, what its token is asked to allow.
    registry_scope: Option<String>,
}

#[derive(Debug, Clone)]
enum At {
    /// A path and query under the configured address, which it starts with a `/` after.
    Path(String),
    /// A whole address.
    Url(String),
}

impl Request {
    /// A GET of `path` (and its query) under the configured address.
    pub fn get(path: impl Into<String>) -> Self {
        Self::of(Method::GET, At::Path(path.into()))
    }

    /// A GET of a whole address, for an operation that learns its host at run time.
    pub fn get_at(url: impl Into<String>) -> Self {
        Self::of(Method::GET, At::Url(url.into()))
    }

    /// A POST of `path` under the configured address.
    pub fn post(path: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            body: Some(body),
            ..Self::of(Method::POST, At::Path(path.into()))
        }
    }

    /// The request is at a container registry, which authenticates in a way of its own, and `scope` is what a token for it
    /// must allow (`repository:<name>:pull`): it goes with nothing at first, and only a challenge brings anything. A token
    /// is presented to the registry as it is. A login goes to the registry if it asks for Basic; if it names an auth host, the
    /// login goes there, a host judged like any other and which the credential's binding must name, and what comes back
    /// goes to the registry.
    pub fn at_a_registry(mut self, scope: impl Into<String>) -> Self {
        self.registry_scope = Some(scope.into());
        self
    }

    /// With this header as well. The credential is not one to add: the handler attaches it.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn of(method: Method, at: At) -> Self {
        Self {
            method,
            at,
            headers: Vec::new(),
            body: None,
            registry_scope: None,
        }
    }
}

/// How the credential was presented, a fact the domain may say in a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presented {
    Nothing,
    Bearer,
    Basic,
}

impl Presented {
    pub fn as_str(self) -> &'static str {
        match self {
            Presented::Nothing => "no credential",
            Presented::Bearer => "Bearer",
            Presented::Basic => "Basic",
        }
    }
}

/// What came back: the response, and facts about the credential. Never the request that was sent or the credential.
#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub presented: Presented,
    /// The secret presented looks like a base64-encoded copy of a token ([`looks_base64`]).
    pub credential_looks_base64: bool,
}

/// Whether a secret looks like a base64-encoded copy of a token: it decodes, under some alphabet, to at least 16 printable
/// bytes. Someone encoded it who should not have, and the site will not accept it.
pub fn looks_base64(token: &str) -> bool {
    let token = token.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .filter_map(|engine| engine.decode(token).ok())
        .any(|decoded| decoded.len() >= 16 && decoded.iter().all(u8::is_ascii_graphic))
}

/// The wait a `Retry-After` header asks for, given the time now: a number of seconds, or an HTTP date (a date already past
/// is no wait). `None` for anything else.
pub fn retry_after(header: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let header = header.trim();
    if !header.is_empty() && header.bytes().all(|b| b.is_ascii_digit()) {
        return header.parse().ok().map(Duration::from_secs);
    }
    let date = chrono::DateTime::parse_from_rfc2822(header).ok()?;
    Some(
        (date.with_timezone(&chrono::Utc) - now)
            .to_std()
            .unwrap_or(Duration::ZERO),
    )
}

/// Renders an error together with every cause beneath it. reqwest reports only "error sending request" at the top; the
/// reason (DNS, TLS, refused, timed out) is in a source, and without it a network failure cannot be told apart from any
/// other.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// What a failure of the client says: never the address, which may carry what a query holds.
fn transport(e: reqwest::Error) -> Failure {
    Failure::Transient(error_chain(&e.without_url()))
}

/// What a registry's challenge asks for, when it names an auth host.
#[derive(Debug, PartialEq, Eq)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
}

/// The first Bearer challenge among a reply's headers, if any: what a server said, so anything else is no challenge.
fn bearer_challenge(headers: &HeaderMap) -> Option<BearerChallenge> {
    headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(http_auth::parser::ChallengeParser::new)
        .filter_map(Result::ok)
        .filter(|challenge| challenge.scheme.eq_ignore_ascii_case("Bearer"))
        .find_map(|challenge| {
            let param = |name: &str| {
                challenge
                    .params
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(name))
                    .map(|(_, value)| value.to_unescaped())
            };
            Some(BearerChallenge {
                realm: param("realm")?,
                service: param("service"),
            })
        })
}

/// What an auth host answers with. Either name is the token's.
#[derive(serde::Deserialize)]
struct TokenReply {
    token: Option<String>,
    access_token: Option<String>,
}

/// The failure a host asking for time comes to, if it is asking.
fn asks_for_time(response: &reqwest::Response) -> Option<Failure> {
    let status = response.status();
    if !matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        return None;
    }
    let wait = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| retry_after(value, chrono::Utc::now()))?;
    Some(Failure::Backoff {
        status: status.as_u16(),
        wait,
    })
}

/// What a registry's challenge comes to: what to present, and when it is a token an auth host gave, how the login was
/// presented for it.
struct Answer {
    presenting: HttpCredential,
    exchanged: Option<(Presented, bool)>,
}

/// Where a request goes: a path under `base`, or its whole address.
fn locate(at: &At, base: Option<&str>) -> Result<Url, String> {
    let text = match (at, base) {
        (At::Path(path), Some(base)) => {
            if !path.starts_with('/') {
                return Err("a path under the configured address must start with /".to_string());
            }
            format!("{}{path}", base.trim().trim_end_matches('/'))
        }
        (At::Path(_), None) => {
            return Err("a path has no address to go under: this operation has none".to_string());
        }
        (At::Url(url), None) => url.clone(),
        (At::Url(_), Some(_)) => {
            return Err(
                "a whole address cannot go under the configured one: give a path".to_string(),
            );
        }
    };
    Url::parse(&text).map_err(|_| "the address cannot be read".to_string())
}

/// What a judgment reads of an address. One that carries a login of its own, or is not http or https, goes nowhere: what
/// it presents is the handler's.
pub(super) fn target_of(url: &Url) -> Result<Target, String> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the address carries a login of its own".to_string());
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err("the address is not http or https".to_string());
    }
    let Some(host) = url.host_str() else {
        return Err("the address has no host".to_string());
    };
    Ok(Target {
        host: host.to_ascii_lowercase(),
        encrypted: url.scheme() == "https",
    })
}

/// The client for what `config` says of the way out: a CA that cannot be used stops the agent, before it does anything,
/// with the variable and the path.
pub(crate) fn start(config: &polar_env::Config) -> Pending<Result<Started, String>> {
    let egress = polar::egress::Egress::read(config).map_err(|e| e.to_string());
    Box::pin(async move {
        let client = Http::client(&egress?, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await?;
        Ok(Arc::new(Http { client }) as Started)
    })
}

/// The HTTP protocol, with its client: one, shared, for the agent.
pub struct Http {
    client: Client,
}

impl Http {
    /// The client: the way out of the cluster the egress settings give, with a bound on opening a connection and on each
    /// request.
    async fn client(
        egress: &polar::egress::Egress,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Client, String> {
        let bundle = egress.ca_bundle().await.map_err(|e| e.to_string())?;
        if !bundle.is_empty() {
            tracing::info!(
                "trusting {} egress CA certificate(s) beside the system's",
                bundle.len()
            );
        }
        egress
            .configure(Self::builder(connect_timeout, request_timeout), &bundle)
            .and_then(ClientBuilder::build)
            .map_err(|e| format!("the HTTP client cannot be built: {}", error_chain(&e)))
    }

    /// What every client has. It follows no redirect by itself: the handler judges each hop.
    pub(crate) fn builder(connect_timeout: Duration, request_timeout: Duration) -> ClientBuilder {
        ClientBuilder::new()
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .redirect(Policy::none())
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// Answers a registry's challenge, or `None` if nothing can, and then its 401 is the reply. The auth host is judged
    /// before anything goes to it: off the credential's binding the request fails, and nothing is sent.
    async fn answer_challenge(
        &self,
        headers: &HeaderMap,
        scope: &str,
        login: Option<HttpCredential>,
        exchange: &mut Exchange<Self>,
    ) -> Result<Option<Answer>, Failure> {
        if let Some(HttpCredential::Bearer(_)) = &login {
            return Ok(login.map(|presenting| Answer {
                presenting,
                exchanged: None,
            }));
        }
        let Some(challenge) = bearer_challenge(headers) else {
            return Ok(login.map(|presenting| Answer {
                presenting,
                exchanged: None,
            }));
        };
        drop(login);
        let mut realm = Url::parse(&challenge.realm).map_err(|_| {
            Failure::Configuration("a registry's auth host cannot be read".to_string())
        })?;
        let target = target_of(&realm).map_err(Failure::Configuration)?;
        let at_realm = exchange.hop(target).await?;
        {
            let mut query = realm.query_pairs_mut();
            query.append_pair("scope", scope);
            if let Some(service) = &challenge.service {
                query.append_pair("service", service);
            }
        }
        let (outgoing, presented, looks) = attach(self.client.get(realm), at_realm)?;
        let mut response = outgoing.send().await.map_err(transport)?;
        if let Some(failure) = asks_for_time(&response) {
            return Err(failure);
        }
        let status = response.status();
        if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
            if presented == Presented::Nothing {
                return Ok(None);
            }
            return Err(Failure::CredentialRefused(format!(
                "the registry's auth host answered {status}"
            )));
        }
        if status != StatusCode::OK {
            return Err(Failure::Transient(format!(
                "the registry's auth host answered {status}"
            )));
        }
        let whole = Zeroizing::new(whole_body(&mut response, MAX_TOKEN_REPLY).await?);
        // What fails to parse says nothing of what it read: a parser's message can repeat it.
        let reply: TokenReply = serde_json::from_slice(&whole).map_err(|_| {
            Failure::Transient("the registry's auth host did not answer with a token".to_string())
        })?;
        let token = reply.token.or(reply.access_token).ok_or_else(|| {
            Failure::Transient("the registry's auth host did not answer with a token".to_string())
        })?;
        Ok(Some(Answer {
            presenting: HttpCredential::Bearer(Zeroizing::new(token.into_bytes())),
            exchanged: Some((presented, looks)),
        }))
    }
}

impl super::sealed::Sealed for Http {}

#[async_trait]
impl Protocol for Http {
    const KIND: ProtocolKind = ProtocolKind::HTTP;
    const BUDGET: Duration = Duration::from_secs(30);
    type Request = Request;
    type Credential = HttpCredential;
    type Reply = Reply;

    fn configured_host(base: &str) -> Result<String, String> {
        let url = Url::parse(base.trim()).map_err(|_| "the address cannot be read".to_string())?;
        target_of(&url).map(|target| target.host)
    }

    fn target(request: &Request, base: Option<&str>) -> Result<Target, String> {
        target_of(&locate(&request.at, base)?)
    }

    async fn credential(
        source: &dyn CredentialSource,
        name: String,
        host: String,
    ) -> Result<HttpCredential, CryptoError> {
        source.http(name, host).await
    }

    async fn perform(
        &self,
        request: Request,
        base: Option<String>,
        credential: Option<HttpCredential>,
        exchange: &mut Exchange<Self>,
    ) -> Result<(), Failure> {
        let mut url = locate(&request.at, base.as_deref()).map_err(Failure::Configuration)?;
        // What the next send presents. A registry's login is held back until a challenge says where it goes.
        let (mut presenting, mut login) = match request.registry_scope {
            None => (credential, None),
            Some(_) => (None, credential),
        };
        let mut exchanged = None;
        let mut challenged = false;
        let mut method = request.method.clone();
        let mut body = request.body.clone();
        for _ in 0..=MAX_HOPS {
            let mut outgoing = self.client.request(method.clone(), url.clone());
            for (name, value) in &request.headers {
                outgoing = outgoing.header(name.as_str(), value.as_str());
            }
            if let Some(body) = &body {
                outgoing = outgoing.body(body.clone());
            }
            let (outgoing, presented, credential_looks_base64) =
                attach(outgoing, presenting.take())?;
            let (presented, credential_looks_base64) =
                exchanged.unwrap_or((presented, credential_looks_base64));
            let mut response = outgoing.send().await.map_err(transport)?;
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
                let target = target_of(&next).map_err(Failure::Configuration)?;
                // A token from an auth host is for where it was presented: it goes no further.
                let there = exchange.hop(target).await?;
                match request.registry_scope {
                    None => presenting = there,
                    Some(_) => {
                        login = there;
                        exchanged = None;
                        challenged = false;
                    }
                }
                // As browsers do: a 303 is a GET, and a 301 or 302 of a POST is too. 307 and 308 keep it as it was.
                if status == StatusCode::SEE_OTHER
                    || (method == Method::POST
                        && matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND))
                {
                    method = Method::GET;
                    body = None;
                }
                url = next;
                continue;
            }

            if let Some(failure) = asks_for_time(&response) {
                return Err(failure);
            }

            if status == StatusCode::UNAUTHORIZED
                && !challenged
                && let Some(scope) = &request.registry_scope
            {
                challenged = true;
                let answer = self
                    .answer_challenge(response.headers(), scope, login.take(), exchange)
                    .await?;
                if let Some(answer) = answer {
                    presenting = Some(answer.presenting);
                    exchanged = answer.exchanged;
                    continue;
                }
            }

            let headers = response.headers().clone();
            let whole = whole_body(&mut response, MAX_BODY).await?;
            exchange
                .reply(Reply {
                    status,
                    headers,
                    body: whole,
                    presented,
                    credential_looks_base64,
                })
                .await;
            return Ok(());
        }
        Err(Failure::Transient(format!(
            "more than {MAX_HOPS} redirects"
        )))
    }
}

/// The whole of a reply's body, up to `most` bytes: past that it is a failure, and no more is read.
async fn whole_body(response: &mut reqwest::Response, most: usize) -> Result<Vec<u8>, Failure> {
    let mut whole = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport)? {
        if whole.len() + chunk.len() > most {
            return Err(Failure::Transient(format!(
                "the reply holds more than {most} bytes"
            )));
        }
        whole.extend_from_slice(&chunk);
    }
    Ok(whole)
}

/// Puts the credential on the request, and says how it was presented. The secret goes no further than this and the client.
fn attach(
    request: reqwest::RequestBuilder,
    credential: Option<HttpCredential>,
) -> Result<(reqwest::RequestBuilder, Presented, bool), Failure> {
    let not_text = || Failure::CredentialUnusable {
        name: "(the one asked for)".to_string(),
        why: "it is not text".to_string(),
    };
    Ok(match credential {
        None => (request, Presented::Nothing, false),
        Some(HttpCredential::Bearer(token)) => {
            let token = std::str::from_utf8(&token).map_err(|_| not_text())?;
            (
                request.bearer_auth(token),
                Presented::Bearer,
                looks_base64(token),
            )
        }
        Some(HttpCredential::Basic { username, password }) => {
            let password = std::str::from_utf8(&password).map_err(|_| not_text())?;
            (
                request.basic_auth(username, Some(password)),
                Presented::Basic,
                looks_base64(password),
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::super::testing::{Site, http_handle_for};
    use super::super::{Credential, Denial, Location, Operation, OperationDecl, ReadFailure};
    use super::*;
    use polar::egress::testing::{TestCa, https_front};
    use polar_crypto::registry::{SecretBinding, SecretKind};
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ca() -> &'static TestCa {
        static CA: OnceLock<TestCa> = OnceLock::new();
        CA.get_or_init(|| TestCa::new("the test site's CA"))
    }

    const SECRET: &str = "the-very-secret-token";

    /// A secret bound to `localhost`, as the CryptoActor would answer for it: the real rule, by the real function.
    fn bound_to_localhost(kind: SecretKind) -> SecretBinding {
        SecretBinding {
            host_pattern: "localhost".to_string(),
            kind,
            username: (kind == SecretKind::UserPassword).then(|| "me@example.org".to_string()),
        }
    }

    const CONFIGURED: OperationDecl = OperationDecl {
        name: "site.read",
        doc: "",
        protocol: ProtocolKind::HTTP,
        location: Location::Configured {
            variable: "SITE_URL",
            credential: Some(Credential::Named("site")),
        },
    };
    const OPEN: OperationDecl = OperationDecl {
        name: "site.read-openly",
        doc: "",
        protocol: ProtocolKind::HTTP,
        location: Location::Configured {
            variable: "SITE_URL",
            credential: None,
        },
    };
    const ANYWHERE: OperationDecl = OperationDecl {
        name: "anywhere.read",
        doc: "",
        protocol: ProtocolKind::HTTP,
        location: Location::Arbitrary,
    };
    const LEARNED: OperationDecl = OperationDecl {
        name: "learned.read",
        doc: "",
        protocol: ProtocolKind::HTTP,
        location: Location::Bound {
            credential: Credential::Named("site"),
        },
    };
    const REGISTRY: OperationDecl = OperationDecl {
        name: "registry.read",
        doc: "",
        protocol: ProtocolKind::HTTP,
        location: Location::Bound {
            credential: Credential::ForHost,
        },
    };
    static DECLARED: [OperationDecl; 5] = [CONFIGURED, OPEN, ANYWHERE, LEARNED, REGISTRY];

    /// What the operations here give: the reply, and one header of it.
    #[derive(Debug)]
    struct Read {
        status: StatusCode,
        body: Vec<u8>,
        fact: Option<String>,
        presented: Presented,
        credential_looks_base64: bool,
    }

    macro_rules! operation {
        ($ty:ident, $decl:ident, $refused:literal) => {
            struct $ty(Request);
            impl Operation for $ty {
                type Protocol = Http;
                type Output = Read;
                const DECL: OperationDecl = $decl;
                fn request(&self) -> Request {
                    self.0.clone()
                }
                fn read(&self, reply: &Reply) -> Result<Read, ReadFailure> {
                    if $refused {
                        return Err(ReadFailure::CredentialRefused("nobody".to_string()));
                    }
                    Ok(Read {
                        status: reply.status,
                        body: reply.body.clone(),
                        fact: reply
                            .headers
                            .get("x-fact")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string),
                        presented: reply.presented,
                        credential_looks_base64: reply.credential_looks_base64,
                    })
                }
            }
        };
    }
    operation!(ConfiguredRead, CONFIGURED, false);
    operation!(OpenRead, OPEN, false);
    operation!(AnywhereRead, ANYWHERE, false);
    operation!(LearnedRead, LEARNED, false);
    operation!(RefusedRead, CONFIGURED, true);
    operation!(RegistryRead, REGISTRY, false);

    struct Fixture {
        server: MockServer,
        site: Site,
        port: u16,
    }

    /// A stand-in site behind TLS on `localhost`, and the handler's way to it: the real client, the real judgment and
    /// the real binding rule.
    async fn fixture(kind: SecretKind) -> Fixture {
        let server = MockServer::start().await;
        let port = https_front(ca(), &server.uri()).await;
        let site = http_handle_for(
            &ca().pem,
            &DECLARED,
            vec![("SITE_URL", format!("https://localhost:{port}"))],
            Some(("site", SECRET, bound_to_localhost(kind))),
        )
        .await;
        Fixture { server, site, port }
    }

    fn authorization(request: &wiremock::Request) -> Option<String> {
        request
            .headers
            .get("authorization")
            .map(|value| value.to_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn a_token_goes_as_bearer_to_its_host_over_real_tls_and_the_reply_comes_back_whole() {
        let f = fixture(SecretKind::Token).await;
        Mock::given(method("GET"))
            .and(path("/a/path"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("the data")
                    .insert_header("x-fact", "yes"),
            )
            .mount(&f.server)
            .await;
        let reply = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/a/path?x=1")))
            .await
            .unwrap();
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, b"the data");
        assert_eq!(reply.fact, Some("yes".to_string()));
        assert_eq!(reply.presented, Presented::Bearer);
        assert!(!reply.credential_looks_base64);
        let received = f.server.received_requests().await.unwrap();
        assert_eq!(
            authorization(&received[0]),
            Some(format!("Bearer {SECRET}"))
        );
        assert_eq!(received[0].url.query(), Some("x=1"));
    }

    /// A secret that looks like a base64 copy of a token is a fact on the reply, and the secret is not.
    #[tokio::test]
    async fn the_reply_says_a_secret_looks_base64_encoded() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let port = https_front(ca(), &server.uri()).await;
        let encoded = STANDARD.encode("a-token-of-more-than-sixteen-characters");
        let site = http_handle_for(
            &ca().pem,
            &DECLARED,
            vec![("SITE_URL", format!("https://localhost:{port}"))],
            Some(("site", &encoded, bound_to_localhost(SecretKind::Token))),
        )
        .await;
        let reply = site
            .handle
            .ask(ConfiguredRead(Request::get("/")))
            .await
            .unwrap();
        assert!(reply.credential_looks_base64);
    }

    #[tokio::test]
    async fn a_user_and_password_goes_as_basic() {
        let f = fixture(SecretKind::UserPassword).await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&f.server)
            .await;
        let reply = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/")))
            .await
            .unwrap();
        assert_eq!(reply.presented, Presented::Basic);
        let expected = format!(
            "Basic {}",
            STANDARD.encode(format!("me@example.org:{SECRET}"))
        );
        let received = f.server.received_requests().await.unwrap();
        assert_eq!(authorization(&received[0]), Some(expected));
    }

    #[tokio::test]
    async fn an_operation_with_no_credential_presents_none() {
        let f = fixture(SecretKind::Token).await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&f.server)
            .await;
        let reply = f
            .site
            .handle
            .ask(OpenRead(Request::get("/")))
            .await
            .unwrap();
        assert_eq!(reply.presented, Presented::Nothing);
        let received = f.server.received_requests().await.unwrap();
        assert_eq!(authorization(&received[0]), None);
    }

    /// A redirect to the same host keeps the credential: asked for again, for where it goes.
    #[tokio::test]
    async fn a_redirect_to_the_bound_host_presents_the_credential_there() {
        let f = fixture(SecretKind::Token).await;
        Mock::given(path("/old"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/new"))
            .mount(&f.server)
            .await;
        Mock::given(path("/new"))
            .respond_with(ResponseTemplate::new(200).set_body_string("moved"))
            .mount(&f.server)
            .await;
        let reply = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/old")))
            .await
            .unwrap();
        assert_eq!(reply.body, b"moved");
        let received = f.server.received_requests().await.unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(
            authorization(&received[1]),
            Some(format!("Bearer {SECRET}"))
        );
        // Each hop is on the record.
        let records = f.site.records.lock().unwrap();
        assert_eq!(records.len(), 2, "{records:?}");
    }

    /// A redirect to another host: the other host is the one the certificate also names, 127.0.0.1, and so a real TLS
    /// server that would take whatever it is sent. It is sent nothing.
    #[tokio::test]
    async fn a_credential_does_not_follow_a_redirect_off_its_host_for_any_operation() {
        let f = fixture(SecretKind::Token).await;
        let elsewhere = format!("https://127.0.0.1:{}/stolen", f.port);
        Mock::given(path("/old"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", elsewhere.as_str()))
            .mount(&f.server)
            .await;

        // Configured: another host is not the one configured.
        let failure = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/old")))
            .await
            .unwrap_err();
        assert_eq!(failure, Failure::Denied(Denial::OffTheConfiguredHost));

        // Learned at run time: another host is not bound.
        let failure = f
            .site
            .handle
            .ask(LearnedRead(Request::get_at(format!(
                "https://localhost:{}/old",
                f.port
            ))))
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            Failure::NotBound {
                name: "site".to_string()
            }
        );
        let received = f.server.received_requests().await.unwrap();
        assert!(
            received.iter().all(|r| r.url.path() != "/stolen"),
            "{received:?}"
        );
    }

    /// An https site that redirects to http does not get the credential sent in the clear.
    #[tokio::test]
    async fn a_credential_does_not_follow_a_redirect_to_a_connection_that_is_not_encrypted() {
        let f = fixture(SecretKind::Token).await;
        let clear = format!("http://localhost:{}/clear", f.server.address().port());
        Mock::given(path("/old"))
            .respond_with(ResponseTemplate::new(301).insert_header("location", clear.as_str()))
            .mount(&f.server)
            .await;
        let failure = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/old")))
            .await
            .unwrap_err();
        assert_eq!(failure, Failure::Denied(Denial::NotEncrypted));
    }

    #[tokio::test]
    async fn a_request_with_no_credential_follows_anywhere_with_the_permission_and_is_marked() {
        let f = fixture(SecretKind::Token).await;
        let elsewhere = format!("https://127.0.0.1:{}/there", f.port);
        Mock::given(path("/here"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", elsewhere.as_str()))
            .mount(&f.server)
            .await;
        Mock::given(path("/there"))
            .respond_with(ResponseTemplate::new(200).set_body_string("there"))
            .mount(&f.server)
            .await;
        let reply = f
            .site
            .handle
            .ask(AnywhereRead(Request::get_at(format!(
                "https://localhost:{}/here",
                f.port
            ))))
            .await
            .unwrap();
        assert_eq!(reply.body, b"there");
        let received = f.server.received_requests().await.unwrap();
        assert!(received.iter().all(|r| authorization(r).is_none()));
        let records = f.site.records.lock().unwrap();
        assert!(
            records
                .iter()
                .all(|r| r.arbitrary && r.credential.is_none()),
            "{records:?}"
        );
        assert_eq!(records.last().unwrap().host, "127.0.0.1");
    }

    #[tokio::test]
    async fn redirects_end() {
        let f = fixture(SecretKind::Token).await;
        Mock::given(path("/loop"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop"))
            .mount(&f.server)
            .await;
        let failure = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/loop")))
            .await
            .unwrap_err();
        assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
        assert_eq!(
            f.server.received_requests().await.unwrap().len(),
            MAX_HOPS + 1
        );
    }

    #[tokio::test]
    async fn a_post_goes_with_its_body_and_a_303_makes_it_a_get() {
        let f = fixture(SecretKind::Token).await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(303).insert_header("location", "/answer"))
            .mount(&f.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/answer"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&f.server)
            .await;
        f.site
            .handle
            .ask(ConfiguredRead(
                Request::post("/graphql", b"{}".to_vec())
                    .header("content-type", "application/json"),
            ))
            .await
            .unwrap();
        let received = f.server.received_requests().await.unwrap();
        assert_eq!(received[0].body, b"{}");
        assert_eq!(
            received[0].headers.get("content-type").unwrap(),
            "application/json"
        );
        assert!(received[1].body.is_empty());
    }

    /// `Retry-After` on a 429 or a 503 keeps the host from being called, and on anything else means nothing.
    #[tokio::test]
    async fn a_host_that_asks_for_time_is_left_alone_for_it() {
        let f = fixture(SecretKind::Token).await;
        Mock::given(path("/busy"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&f.server)
            .await;
        Mock::given(path("/other"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&f.server)
            .await;
        let failure = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/busy")))
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            Failure::Backoff {
                status: 429,
                wait: Duration::from_secs(60)
            }
        );
        let failure = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/other")))
            .await
            .unwrap_err();
        assert!(matches!(failure, Failure::NotYet { .. }), "{failure:?}");
        assert_eq!(f.server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn other_statuses_are_the_operations_to_read() {
        let f = fixture(SecretKind::Token).await;
        for status in [401u16, 403, 404, 500, 503] {
            let at = format!("/{status}");
            Mock::given(path(at.as_str()))
                .respond_with(
                    ResponseTemplate::new(status).insert_header("retry-after", "nonsense"),
                )
                .mount(&f.server)
                .await;
            let reply = f
                .site
                .handle
                .ask(ConfiguredRead(Request::get(at)))
                .await
                .unwrap();
            assert_eq!(reply.status.as_u16(), status);
        }
    }

    /// `read` saying that the answer means the credential is not accepted is held, by the handler.
    #[tokio::test]
    async fn a_read_that_finds_the_credential_refused_stops_it_being_presented() {
        let f = fixture(SecretKind::Token).await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&f.server)
            .await;
        let failure = f
            .site
            .handle
            .ask(RefusedRead(Request::get("/")))
            .await
            .unwrap_err();
        assert_eq!(failure, Failure::CredentialRefused("nobody".to_string()));
        let failure = f
            .site
            .handle
            .ask(ConfiguredRead(Request::get("/")))
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            Failure::CredentialHeld {
                name: "site".to_string()
            }
        );
        assert_eq!(f.server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_host_that_cannot_be_reached_is_transient_and_the_message_has_no_address() {
        let site = http_handle_for(
            &ca().pem,
            &DECLARED,
            vec![("SITE_URL", "https://localhost:1".to_string())],
            Some(("site", SECRET, bound_to_localhost(SecretKind::Token))),
        )
        .await;
        let failure = site
            .handle
            .ask(ConfiguredRead(Request::get("/a?secret-query=1")))
            .await
            .unwrap_err();
        let Failure::Transient(why) = failure else {
            panic!("{failure:?}");
        };
        assert!(!why.contains("secret-query"), "{why}");
        assert!(!why.contains(SECRET), "{why}");
    }

    /// A certificate the agent does not trust is a failure, not a request.
    #[tokio::test]
    async fn a_host_whose_certificate_is_not_trusted_is_sent_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let port = https_front(&TestCa::new("not the one trusted"), &server.uri()).await;
        let site = http_handle_for(
            &ca().pem,
            &DECLARED,
            vec![("SITE_URL", format!("https://localhost:{port}"))],
            Some(("site", SECRET, bound_to_localhost(SecretKind::Token))),
        )
        .await;
        let failure = site
            .handle
            .ask(ConfiguredRead(Request::get("/")))
            .await
            .unwrap_err();
        assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_reply_past_the_bound_is_a_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1024]))
            .mount(&server)
            .await;
        let client = Client::new();
        let mut response = client.get(server.uri()).send().await.unwrap();
        assert!(matches!(
            whole_body(&mut response, 1023).await,
            Err(Failure::Transient(_))
        ));
        let mut response = client.get(server.uri()).send().await.unwrap();
        assert_eq!(whole_body(&mut response, 1024).await.unwrap().len(), 1024);
    }

    #[tokio::test]
    async fn a_request_that_takes_too_long_is_given_up() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let client = Http::client(
            &polar::egress::Egress::default(),
            Duration::from_secs(5),
            Duration::from_millis(200),
        )
        .await
        .unwrap();

        let started = std::time::Instant::now();
        let error = client.get(server.uri()).send().await.unwrap_err();
        assert!(error.is_timeout(), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn a_connection_that_never_opens_is_given_up() {
        // A listener that never accepts: the kernel completes the TCP handshake, and the TLS
        // handshake then waits for an answer that never comes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = Http::client(
            &polar::egress::Egress::default(),
            Duration::from_millis(200),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

        let started = std::time::Instant::now();
        let sent = tokio::time::timeout(
            Duration::from_secs(5),
            client.get(format!("https://{address}/")).send(),
        )
        .await;
        let error = sent
            .expect("the connect timeout did not end the request")
            .unwrap_err();
        assert!(error.is_connect() || error.is_timeout(), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(listener);
    }

    /// The image's roots (SSL_CERT_FILE, read from the process environment, so the client is made in a child
    /// process) and the egress CA are trusted together: a site behind a TLS-inspecting proxy and one that is not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_egress_ca_is_trusted_beside_the_image_roots() {
        use polar::egress::testing::{given, https_server, rerun};
        if let Some(urls) = given("HTTP_TEST_URLS") {
            let egress = polar::egress::Egress {
                ca_cert: given("POLAR_EGRESS_CA_CERT"),
                ..polar::egress::Egress::default()
            };
            let client = Http::client(&egress, CONNECT_TIMEOUT, REQUEST_TIMEOUT)
                .await
                .unwrap();
            for url in urls.split(',') {
                let body = client.get(url).send().await.unwrap().text().await.unwrap();
                assert_eq!(body, "ok", "{url}");
            }
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let image = TestCa::new("image roots");
        let corporate = TestCa::new("corporate root");
        let image_file = image.write(dir.path(), "image.pem");
        let corporate_file = corporate.write(dir.path(), "corporate.pem");
        let urls = format!(
            "{},{}",
            https_server(&image).await.url,
            https_server(&corporate).await.url
        );
        let output = rerun(
            "protocol::http::tests::the_egress_ca_is_trusted_beside_the_image_roots",
            &[
                ("SSL_CERT_FILE", image_file.to_str().unwrap()),
                ("POLAR_EGRESS_CA_CERT", corporate_file.to_str().unwrap()),
                ("HTTP_TEST_URLS", &urls),
            ],
        )
        .await;
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    const SCOPE: &str = "repository:team/app:pull";
    const TOKEN_FROM_THE_AUTH_HOST: &str = "a-token-from-the-auth-host";

    fn manifest_url(host: &str, port: u16) -> String {
        format!("https://{host}:{port}/v2/team/app/manifests/1")
    }

    fn at_a_registry(host: &str, port: u16) -> Request {
        Request::get_at(manifest_url(host, port)).at_a_registry(SCOPE)
    }

    /// The registry: it answers `Bearer` with its manifest, and anything else with a challenge to go to `realm`.
    async fn registry_challenging(server: &MockServer, realm: &str) {
        Mock::given(path("/v2/team/app/manifests/1"))
            .and(wiremock::matchers::header(
                "authorization",
                format!("Bearer {TOKEN_FROM_THE_AUTH_HOST}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("the manifest"))
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(
                ResponseTemplate::new(401).insert_header(
                    "www-authenticate",
                    format!(
                        r#"Bearer realm="{realm}",service="the-registry",scope="ignored:by:us""#
                    )
                    .as_str(),
                ),
            )
            .with_priority(2)
            .mount(server)
            .await;
    }

    async fn auth_host_giving_a_token(server: &MockServer) {
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"token":"{TOKEN_FROM_THE_AUTH_HOST}","expires_in":60}}"#
            )))
            .mount(server)
            .await;
    }

    async fn requests_to(server: &MockServer, at: &str) -> Vec<wiremock::Request> {
        server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.url.path() == at)
            .collect()
    }

    fn basic_login() -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("me@example.org:{SECRET}"))
        )
    }

    #[tokio::test]
    async fn a_registry_that_challenges_nothing_is_presented_nothing() {
        let f = fixture(SecretKind::UserPassword).await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("the manifest"))
            .mount(&f.server)
            .await;
        let read = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"the manifest");
        assert_eq!(read.presented, Presented::Nothing);
        let asked = requests_to(&f.server, "/v2/team/app/manifests/1").await;
        assert_eq!(asked.len(), 1);
        assert_eq!(authorization(&asked[0]), None);
    }

    /// The whole of it: the login goes to the auth host and nowhere else, the registry sees only what came back, and the
    /// domain sees neither.
    #[tokio::test]
    async fn a_login_goes_to_the_auth_host_and_only_its_token_to_the_registry() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://localhost:{}/token", f.port);
        registry_challenging(&f.server, &realm).await;
        auth_host_giving_a_token(&f.server).await;

        let read = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"the manifest");
        assert_eq!(read.presented, Presented::Basic);
        let seen = format!("{read:?}");
        assert!(
            !seen.contains(SECRET) && !seen.contains(TOKEN_FROM_THE_AUTH_HOST),
            "{seen}"
        );

        let token_asks = requests_to(&f.server, "/token").await;
        assert_eq!(token_asks.len(), 1);
        assert_eq!(authorization(&token_asks[0]), Some(basic_login()));
        let query: HashMap<String, String> = token_asks[0].url.query_pairs().into_owned().collect();
        assert_eq!(query.get("scope").map(String::as_str), Some(SCOPE));
        assert_eq!(
            query.get("service").map(String::as_str),
            Some("the-registry")
        );

        let manifest_asks = requests_to(&f.server, "/v2/team/app/manifests/1").await;
        assert_eq!(
            manifest_asks.iter().map(authorization).collect::<Vec<_>>(),
            vec![None, Some(format!("Bearer {TOKEN_FROM_THE_AUTH_HOST}"))]
        );

        let records = f.site.records.lock().unwrap().clone();
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(records.iter().all(|record| {
            record.operation == "registry.read"
                && record.credential.as_deref() == Some("site")
                && record.verdict == "allowed"
        }));
    }

    /// The registry says where the login goes, and it is not to be believed: this is what oci-client does not check.
    #[tokio::test]
    async fn an_auth_host_off_the_binding_is_sent_nothing_and_the_request_fails() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://127.0.0.1:{}/token", f.port);
        registry_challenging(&f.server, &realm).await;
        auth_host_giving_a_token(&f.server).await;

        let failure = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap_err();
        assert_eq!(
            failure,
            Failure::NotBound {
                name: "site".to_string()
            }
        );
        assert!(requests_to(&f.server, "/token").await.is_empty());
        for request in f.server.received_requests().await.unwrap() {
            assert_eq!(authorization(&request), None, "{request:?}");
        }
    }

    #[tokio::test]
    async fn an_auth_host_over_a_connection_not_encrypted_is_sent_no_login() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("{}/token", f.server.uri().replace("127.0.0.1", "localhost"));
        registry_challenging(&f.server, &realm).await;
        auth_host_giving_a_token(&f.server).await;

        let failure = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap_err();
        assert_eq!(failure, Failure::Denied(Denial::NotEncrypted));
        assert!(requests_to(&f.server, "/token").await.is_empty());
    }

    /// A public image at a registry that wants a token for everything: nothing of the agent's is presented, and the request
    /// is on the record, each place it went, as the permission it is.
    #[tokio::test]
    async fn with_no_credential_a_token_is_asked_for_with_nothing_and_each_host_is_marked() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://127.0.0.1:{}/token", f.port);
        registry_challenging(&f.server, &realm).await;
        auth_host_giving_a_token(&f.server).await;

        let read = f
            .site
            .handle
            .ask(AnywhereRead(at_a_registry("127.0.0.1", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"the manifest");
        assert_eq!(read.presented, Presented::Nothing);
        assert_eq!(
            authorization(&requests_to(&f.server, "/token").await[0]),
            None
        );
        let records = f.site.records.lock().unwrap().clone();
        assert_eq!(records.len(), 2, "{records:?}");
        assert!(
            records
                .iter()
                .all(|r| r.arbitrary && r.credential.is_none())
        );
    }

    #[tokio::test]
    async fn a_registry_that_asks_for_basic_is_given_the_login() {
        let f = fixture(SecretKind::UserPassword).await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .and(wiremock::matchers::header(
                "authorization",
                basic_login().as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("the manifest"))
            .with_priority(1)
            .mount(&f.server)
            .await;
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("www-authenticate", r#"Basic realm="the-registry""#),
            )
            .with_priority(2)
            .mount(&f.server)
            .await;
        let read = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"the manifest");
        assert_eq!(read.presented, Presented::Basic);
    }

    /// A token is the registry's own, and goes to it whatever the challenge names: nothing goes to the auth host.
    #[tokio::test]
    async fn a_token_goes_to_the_registry_and_not_to_the_auth_host_it_names() {
        let f = fixture(SecretKind::Token).await;
        let realm = format!("https://localhost:{}/token", f.port);
        Mock::given(path("/v2/team/app/manifests/1"))
            .and(wiremock::matchers::header(
                "authorization",
                format!("Bearer {SECRET}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("the manifest"))
            .with_priority(1)
            .mount(&f.server)
            .await;
        registry_challenging(&f.server, &realm).await;
        auth_host_giving_a_token(&f.server).await;
        let read = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"the manifest");
        assert_eq!(read.presented, Presented::Bearer);
        assert!(requests_to(&f.server, "/token").await.is_empty());
    }

    #[tokio::test]
    async fn a_login_the_auth_host_refuses_is_held() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://localhost:{}/token", f.port);
        registry_challenging(&f.server, &realm).await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&f.server)
            .await;
        let failure = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap_err();
        assert!(
            matches!(failure, Failure::CredentialRefused(_)),
            "{failure:?}"
        );
        let again = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap_err();
        assert_eq!(
            again,
            Failure::CredentialHeld {
                name: "site".to_string()
            }
        );
        assert_eq!(requests_to(&f.server, "/token").await.len(), 1);
    }

    /// An auth host that gives nobody a token for this: the registry's own 401 is what the operation reads.
    #[tokio::test]
    async fn with_no_credential_an_auth_host_that_refuses_leaves_the_registrys_answer() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://127.0.0.1:{}/token", f.port);
        registry_challenging(&f.server, &realm).await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&f.server)
            .await;
        let read = f
            .site
            .handle
            .ask(AnywhereRead(at_a_registry("127.0.0.1", f.port)))
            .await
            .unwrap();
        assert_eq!(read.status, StatusCode::UNAUTHORIZED);
        assert_eq!(read.presented, Presented::Nothing);
    }

    /// One challenge is answered once. The registry saying no to what it asked for is the operation's to read, with how the
    /// credential was presented, and not a loop.
    #[tokio::test]
    async fn a_registry_that_refuses_the_answer_is_not_asked_again() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://localhost:{}/token", f.port);
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                format!(r#"Bearer realm="{realm}""#).as_str(),
            ))
            .mount(&f.server)
            .await;
        auth_host_giving_a_token(&f.server).await;
        let read = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap();
        assert_eq!(read.status, StatusCode::UNAUTHORIZED);
        assert_eq!(read.presented, Presented::Basic);
        assert_eq!(
            requests_to(&f.server, "/v2/team/app/manifests/1")
                .await
                .len(),
            2
        );
        assert_eq!(requests_to(&f.server, "/token").await.len(), 1);
    }

    /// A token is for the host it was presented to: a redirect off it takes nothing along.
    #[tokio::test]
    async fn a_token_from_the_auth_host_does_not_follow_a_redirect() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://127.0.0.1:{}/token", f.port);
        let elsewhere = format!("https://localhost:{}/elsewhere", f.port);
        Mock::given(path("/v2/team/app/manifests/1"))
            .and(wiremock::matchers::header(
                "authorization",
                format!("Bearer {TOKEN_FROM_THE_AUTH_HOST}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(307).insert_header("location", elsewhere.as_str()))
            .with_priority(1)
            .mount(&f.server)
            .await;
        registry_challenging(&f.server, &realm).await;
        auth_host_giving_a_token(&f.server).await;
        Mock::given(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200).set_body_string("from elsewhere"))
            .mount(&f.server)
            .await;
        let read = f
            .site
            .handle
            .ask(AnywhereRead(at_a_registry("127.0.0.1", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"from elsewhere");
        assert_eq!(
            authorization(&requests_to(&f.server, "/elsewhere").await[0]),
            None
        );
    }

    /// A hop gives what may go to the next host, and at a registry that too waits to be asked for.
    #[tokio::test]
    async fn a_redirect_at_a_registry_presents_nothing_until_it_is_asked_for() {
        let f = fixture(SecretKind::UserPassword).await;
        let next = format!("https://localhost:{}/elsewhere", f.port);
        Mock::given(path("/v2/team/app/manifests/1"))
            .respond_with(ResponseTemplate::new(307).insert_header("location", next.as_str()))
            .mount(&f.server)
            .await;
        Mock::given(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200).set_body_string("from elsewhere"))
            .mount(&f.server)
            .await;
        let read = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"from elsewhere");
        assert_eq!(read.presented, Presented::Nothing);
        assert_eq!(
            authorization(&requests_to(&f.server, "/elsewhere").await[0]),
            None
        );
    }

    #[tokio::test]
    async fn an_auth_host_that_asks_for_time_or_gives_no_token_says_so_and_nothing_of_what_it_said()
    {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://localhost:{}/token", f.port);
        registry_challenging(&f.server, &realm).await;
        let token_replies = [
            ResponseTemplate::new(200).set_body_string(format!("not json {SECRET}")),
            ResponseTemplate::new(200).set_body_string(r#"{"expires_in":60}"#),
            ResponseTemplate::new(500).set_body_string(SECRET),
        ];
        for reply in token_replies {
            let answering = Mock::given(path("/token"))
                .respond_with(reply)
                .mount_as_scoped(&f.server)
                .await;
            let failure = f
                .site
                .handle
                .ask(RegistryRead(at_a_registry("localhost", f.port)))
                .await
                .unwrap_err();
            assert!(matches!(failure, Failure::Transient(_)), "{failure:?}");
            assert!(!failure.to_string().contains(SECRET), "{failure}");
            drop(answering);
        }
        // Bounded before it is parsed: the last of them is read no further than its limit.
        let last = Mock::given(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_TOKEN_REPLY + 1]),
            )
            .mount_as_scoped(&f.server)
            .await;
        let failure = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap_err();
        assert!(failure.to_string().contains("bytes"), "{failure}");
        drop(last);
        let _answering = Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount_as_scoped(&f.server)
            .await;
        let failure = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap_err();
        assert!(
            matches!(failure, Failure::Backoff { status: 429, .. }),
            "{failure:?}"
        );
    }

    #[tokio::test]
    async fn an_access_token_is_a_token() {
        let f = fixture(SecretKind::UserPassword).await;
        let realm = format!("https://localhost:{}/token", f.port);
        registry_challenging(&f.server, &realm).await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"access_token":"{TOKEN_FROM_THE_AUTH_HOST}"}}"#
            )))
            .mount(&f.server)
            .await;
        let read = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("localhost", f.port)))
            .await
            .unwrap();
        assert_eq!(read.body, b"the manifest");
    }

    /// No binding names the host: nothing is sent, so the domain can go on to the operation with no credential.
    #[tokio::test]
    async fn a_host_no_credential_is_bound_to_is_denied_before_anything_is_sent() {
        let f = fixture(SecretKind::UserPassword).await;
        let failure = f
            .site
            .handle
            .ask(RegistryRead(at_a_registry("127.0.0.1", f.port)))
            .await
            .unwrap_err();
        assert_eq!(failure, Failure::Denied(Denial::NoCredentialBound));
        assert!(f.server.received_requests().await.unwrap().is_empty());
    }

    fn challenge_of(header: &str) -> Option<BearerChallenge> {
        let mut headers = HeaderMap::new();
        headers.insert(WWW_AUTHENTICATE, header.parse().unwrap());
        bearer_challenge(&headers)
    }

    #[test]
    fn a_challenge_is_read_as_a_registry_writes_it() {
        assert_eq!(
            challenge_of(
                r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull""#
            ),
            Some(BearerChallenge {
                realm: "https://auth.docker.io/token".to_string(),
                service: Some("registry.docker.io".to_string()),
            })
        );
        assert_eq!(
            challenge_of(r#"bearer REALM="https://ghcr.io/token""#),
            Some(BearerChallenge {
                realm: "https://ghcr.io/token".to_string(),
                service: None,
            })
        );
        // Among others, and after one of another kind.
        assert_eq!(
            challenge_of(r#"Basic realm="a", Bearer realm="https://b.example.org/t""#)
                .map(|c| c.realm),
            Some("https://b.example.org/t".to_string())
        );
        for no_challenge in [r#"Basic realm="a""#, "Bearer", r#"Bearer service="a""#, ""] {
            assert_eq!(challenge_of(no_challenge), None, "{no_challenge}");
        }
    }

    proptest! {
        /// A challenge is what a server said: anything at all comes to a challenge or none, and never to a panic.
        #[test]
        fn anything_a_server_says_is_a_challenge_or_is_not(header in "[ -~]{0,120}") {
            let _ = challenge_of(&header);
        }

        #[test]
        fn a_realm_and_a_service_come_back_as_they_were_written(
            realm in "https://[a-z]{1,10}\\.example\\.org/[a-z]{0,10}",
            service in "[a-zA-Z0-9.:-]{1,20}",
        ) {
            prop_assert_eq!(
                challenge_of(&format!(r#"Bearer realm="{realm}",service="{service}""#)),
                Some(BearerChallenge { realm, service: Some(service) })
            );
        }
    }

    /// Every certificate of the file: a bundle read as one would leave the second host untrusted.
    #[tokio::test]
    async fn every_certificate_of_the_egress_ca_is_trusted() {
        use polar::egress::testing::https_server;
        let dir = tempfile::tempdir().unwrap();
        let first = TestCa::new("first root");
        let second = TestCa::new("second root");
        let bundle = dir.path().join("bundle.pem");
        std::fs::write(&bundle, format!("{}{}", first.pem, second.pem)).unwrap();
        let egress = polar::egress::Egress {
            ca_cert: Some(bundle.display().to_string()),
            ..polar::egress::Egress::default()
        };
        let client = Http::client(&egress, CONNECT_TIMEOUT, REQUEST_TIMEOUT)
            .await
            .unwrap();
        for server in [https_server(&first).await, https_server(&second).await] {
            let answer = client.get(&server.url).send().await;
            assert!(answer.is_ok(), "{}: {answer:?}", server.url);
            assert!(server.served() > 0, "{} was not reached", server.url);
        }
    }

    /// A trust root that was asked for is not silently left out: the agent does not start.
    #[tokio::test]
    async fn an_egress_ca_that_cannot_be_read_or_used_stops_the_agent() {
        let unreadable = polar::egress::Egress {
            ca_cert: Some("/nonexistent/egress-ca.pem".to_string()),
            ..polar::egress::Egress::default()
        };
        let why = Http::client(&unreadable, CONNECT_TIMEOUT, REQUEST_TIMEOUT)
            .await
            .expect_err("an error");
        assert!(
            why.contains("POLAR_EGRESS_CA_CERT") && why.contains("/nonexistent/egress-ca.pem"),
            "{why}"
        );

        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.pem");
        std::fs::write(
            &bad,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let unusable = polar::egress::Egress {
            ca_cert: Some(bad.display().to_string()),
            ..polar::egress::Egress::default()
        };
        assert!(
            Http::client(&unusable, CONNECT_TIMEOUT, REQUEST_TIMEOUT)
                .await
                .is_err()
        );
    }

    /// The way out the cluster names is the way out, and a host it says to bypass is reached directly.
    #[tokio::test]
    async fn a_request_goes_through_the_egress_proxy_unless_its_host_bypasses_it() {
        use polar::egress::testing::{https_server, recording_proxy};
        let (proxy, seen) = recording_proxy().await;
        let local = TestCa::new("bypassed");
        let bypassed = https_server(&local).await;
        let dir = tempfile::tempdir().unwrap();
        let egress = polar::egress::Egress {
            proxy: Some(proxy),
            no_proxy: Some("127.0.0.1".to_string()),
            ca_cert: Some(local.write(dir.path(), "ca.pem").display().to_string()),
        };
        let client = Http::client(&egress, CONNECT_TIMEOUT, Duration::from_secs(5))
            .await
            .unwrap();
        let _ = client.get("https://registry.example.org/v2/").send().await;
        assert_eq!(
            seen.lock().unwrap().first().map(String::as_str),
            Some("CONNECT registry.example.org:443 HTTP/1.1")
        );
        let answer = client.get(&bypassed.url).send().await;
        assert!(answer.is_ok(), "{answer:?}");
        assert_eq!(seen.lock().unwrap().len(), 1, "{seen:?}");
    }

    #[test]
    fn a_location_is_read_as_the_operation_declares_it() {
        let host =
            |request: &Request, base: Option<&str>| Http::target(request, base).map(|t| t.host);
        let base = Some("https://Jira.Example.org/jira/");
        assert_eq!(
            host(&Request::get("/rest"), base).as_deref(),
            Ok("jira.example.org")
        );
        assert!(
            Http::target(&Request::get("/rest"), base)
                .unwrap()
                .encrypted
        );
        assert!(
            !Http::target(&Request::get("/"), Some("http://jira.example.org"))
                .unwrap()
                .encrypted
        );
        assert_eq!(
            locate(&At::Path("/rest".to_string()), base)
                .unwrap()
                .as_str(),
            "https://jira.example.org/jira/rest"
        );
        for (request, base) in [
            (Request::get("no-leading-slash"), base),
            (Request::get("@evil.example.org/"), base),
            (Request::get("/a"), None),
            (Request::get_at("https://a.example.org/"), base),
            (Request::get_at("not an address"), None),
            (Request::get_at("https://me:pw@a.example.org/"), None),
            (Request::get_at("ftp://a.example.org/"), None),
        ] {
            assert!(
                Http::target(&request, base).is_err(),
                "{request:?} {base:?}"
            );
        }
    }

    #[test]
    fn retry_after_is_read_as_seconds_or_as_a_date() {
        let now = chrono::DateTime::parse_from_rfc2822("Wed, 21 Oct 2015 07:28:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(retry_after("120", now), Some(Duration::from_secs(120)));
        assert_eq!(retry_after(" 0 ", now), Some(Duration::ZERO));
        assert_eq!(
            retry_after("Wed, 21 Oct 2015 07:30:30 GMT", now),
            Some(Duration::from_secs(150))
        );
        // A date already past is no wait.
        assert_eq!(
            retry_after("Wed, 21 Oct 2015 07:00:00 GMT", now),
            Some(Duration::ZERO)
        );
        for nonsense in ["", "soon", "-5", "1.5"] {
            assert_eq!(retry_after(nonsense, now), None, "{nonsense:?}");
        }
    }

    #[test]
    fn a_base64_copy_of_a_token_is_noticed() {
        let raw = "ATATT3xFfGF0Qm9ndXNUb2tlbkZvclRlc3Rpbmc=A1B2C3D4";
        assert!(!looks_base64(raw), "the raw token itself");
        assert!(looks_base64(&STANDARD.encode(raw)));
        assert!(looks_base64(&URL_SAFE_NO_PAD.encode(raw)));
        assert!(looks_base64(&format!("{}\n", STANDARD.encode(raw))));
    }

    #[test]
    fn a_data_center_token_or_a_short_one_is_not_taken_for_a_copy() {
        // A Data Center personal access token: 44 characters of base64, of an id, a colon and
        // random bytes.
        let mut pat = b"471706345638:".to_vec();
        pat.extend([
            0xb0, 0x58, 0x1f, 0x9c, 0x02, 0xe7, 0x44, 0x81, 0x3a, 0xff, 0x10, 0x6d, 0xc2, 0x99,
            0x07, 0x5e, 0xa1, 0x30, 0x8b, 0xd4,
        ]);
        let pat = STANDARD.encode(&pat);
        assert_eq!(pat.len(), 44);
        assert!(!looks_base64(&pat));
        // Too short to say: "short-token" decodes to fewer than 16 characters.
        assert!(!looks_base64(&STANDARD.encode("short-token")));
        // Whitespace in what it decodes to is not a token.
        assert!(!looks_base64(
            &STANDARD.encode("a phrase with spaces in it")
        ));
        assert!(!looks_base64("t0ken"));
    }

    proptest! {
        #[test]
        fn a_base64_copy_of_any_printable_token_is_noticed(token in "[!-~]{16,64}") {
            for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
                let encoded = engine.encode(&token);
                prop_assert!(looks_base64(&encoded), "{}", encoded);
            }
        }

        #[test]
        fn printable_text_with_one_other_byte_in_it_is_never_noticed(
            mut bytes in proptest::collection::vec(0x21u8..=0x7e, 15..63),
            odd in prop_oneof![0u8..=0x20, 0x7fu8..=0xff],
            at in any::<proptest::sample::Index>(),
        ) {
            let at = at.index(bytes.len() + 1);
            bytes.insert(at, odd);
            for engine in [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
                prop_assert!(!looks_base64(&engine.encode(&bytes)));
            }
        }

        #[test]
        fn a_data_center_shaped_token_is_not_noticed(blob in proptest::collection::vec(any::<u8>(), 33)) {
            // 33 random bytes as 44 characters of base64, the shape of a personal access token. All
            // 33 are printable with probability (94/256)^33, about 5e-15.
            prop_assert!(!looks_base64(&STANDARD.encode(&blob)));
        }

        /// Whatever a path holds, it cannot move the request off the configured host: it reads as that host, or as nothing.
        #[test]
        fn no_path_moves_a_request_off_the_configured_host(path in "[ -~]{0,40}") {
            if let Ok(target) = Http::target(&Request::get(path.clone()), Some("https://site.example.org/ctx")) {
                prop_assert_eq!(target.host, "site.example.org", "{}", path);
            }
        }
    }
}
