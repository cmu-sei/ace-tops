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

//! The egress probe (`--probe-egress URL`, docs/architecture/egress.md, "The probe"): whether the agent's way out of the
//! cluster reaches a URL. Each protocol the agent goes out with makes one request of it, with the egress settings the agent
//! runs with (its proxy, its bypass list, the CAs it trusts) and with no credential, and says what came of it. The request
//! is the protocol's own, made by its own client: what the probe finds is what the agent's requests would find.
//!
//! It reports and decides nothing: an operator, or `up.nu`, reads the verdict.

use super::{Pending, ProtocolKind, Started};
use polar::egress::Egress;
use serde::{Deserialize, Serialize};

/// How a protocol makes the probe's request: given what it started as, the URL, and whether the way there is through the
/// proxy, what came of it.
pub(crate) type Prober = fn(Started, String, bool) -> Pending<Probed>;

/// What came of the probe's request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// Something at the URL answered, whatever it said: the way out works.
    Reached,
    /// The name could not be resolved.
    Dns,
    /// The name resolved, and nothing could be connected to, or the attempt took longer than the protocol's bound.
    Unreachable,
    /// A connection was made, and its certificate is not one the agent trusts (or something in between presents its own).
    Tls,
    /// The way out is through a proxy, and the proxy could not be reached or would not open the way.
    Proxy,
    /// Anything else, said in the detail.
    Other,
}

/// What came of the probe's request, and what was said of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probed {
    pub reach: Reach,
    pub detail: String,
}

impl Probed {
    pub fn new(reach: Reach, detail: impl Into<String>) -> Self {
        Self {
            reach,
            detail: detail.into(),
        }
    }
}

/// The line the probe prints for one protocol: JSON, one object. It names the URL's host and never the rest of the URL, which
/// may carry what a query holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeLine {
    pub agent: String,
    pub protocol: String,
    pub host: String,
    pub verdict: Reach,
    pub detail: String,
}

// What an error of the client says, as libgit2, reqwest and the system put it.
const TLS: &[&str] = &["certificate", "ssl", "tls"];
const PROXY: &[&str] = &["proxy", "tunnel"];
const DNS: &[&str] = &[
    "dns error",
    "failed to lookup address",
    "failed to resolve address",
    "could not resolve",
    "name or service not known",
    "name does not resolve",
    "temporary failure in name resolution",
    "no address associated",
];
const UNREACHABLE: &[&str] = &[
    "connection refused",
    "failed to connect",
    "tcp connect error",
    "timed out",
    "network is unreachable",
    "no route to host",
    "connection reset",
];

/// What a failed request's error says, read in a fixed order: a certificate first, since a tunnel that opened and a TLS that
/// did not is the destination's certificate; then the proxy; then, where the way out is through a proxy, any failure to
/// connect is the proxy's, since the agent resolves and connects to nothing else; then a name, then a connection.
pub fn classify(message: &str, proxied: bool) -> Probed {
    let lower = message.to_ascii_lowercase();
    let says = |words: &[&str]| words.iter().any(|w| lower.contains(w));
    let reach = if says(TLS) {
        Reach::Tls
    } else if says(PROXY) || (proxied && (says(DNS) || says(UNREACHABLE))) {
        Reach::Proxy
    } else if says(DNS) {
        Reach::Dns
    } else if says(UNREACHABLE) {
        Reach::Unreachable
    } else {
        Reach::Other
    };
    Probed::new(reach, message)
}

/// Every protocol among `operations` that goes outside the cluster and can be probed, each once, in the order declared.
pub fn outside(operations: &[super::OperationDecl]) -> Vec<ProtocolKind> {
    let mut kinds: Vec<ProtocolKind> = Vec::new();
    for operation in operations {
        let kind = operation.protocol;
        if kind.goes_out() && kind.prober().is_some() && !kinds.contains(&kind) {
            kinds.push(kind);
        }
    }
    kinds
}

/// The host of `url`, or None if it is not an address with one.
fn host_of(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()?
        .host_str()
        .map(|host| host.to_ascii_lowercase())
}

/// The detail, with the URL replaced by its host wherever it appears.
fn scrubbed(detail: &str, url: &str, host: &str) -> String {
    if url.is_empty() {
        detail.to_string()
    } else {
        detail.replace(url, host)
    }
}

/// Probes `url` with each of `kinds`, as `config` says the way out is: one line each.
pub async fn probe(
    agent: &str,
    kinds: &[ProtocolKind],
    config: &polar_env::Config,
    url: &str,
) -> Vec<ProbeLine> {
    let host = host_of(url);
    let mut lines = Vec::new();
    for kind in kinds {
        let probed = match (&host, kind.prober()) {
            (None, _) => Probed::new(Reach::Other, "the URL cannot be read, or has no host"),
            (Some(_), None) => Probed::new(Reach::Other, "this protocol is not probed"),
            (Some(_), Some(prober)) => match Egress::read(config) {
                Err(e) => Probed::new(Reach::Other, e.to_string()),
                Ok(egress) => match (kind.start)(config).await {
                    Err(e) => Probed::new(Reach::Other, e),
                    Ok(started) => {
                        let proxied = egress.proxy_for(url).is_some();
                        prober(started, url.to_string(), proxied).await
                    }
                },
            },
        };
        let host = host.clone().unwrap_or_default();
        lines.push(ProbeLine {
            agent: agent.to_string(),
            protocol: kind.as_str().to_string(),
            detail: scrubbed(&probed.detail, url, &host),
            host,
            verdict: probed.reach,
        });
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn what_the_clients_say_is_read_as_the_verdict_it_means() {
        for (message, proxied, reach) in [
            // reqwest's, as `error_chain` puts it.
            (
                "error sending request: client error (Connect): dns error: failed to lookup address information: Name or service not known",
                false,
                Reach::Dns,
            ),
            (
                "error sending request: client error (Connect): tcp connect error: Connection refused (os error 111)",
                false,
                Reach::Unreachable,
            ),
            (
                "error sending request: client error (Connect): error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed",
                false,
                Reach::Tls,
            ),
            (
                "error sending request: client error (Connect): unsuccessful tunnel",
                true,
                Reach::Proxy,
            ),
            // Through a proxy, a name or a connection that fails is the proxy's.
            (
                "error sending request: client error (Connect): tcp connect error: Connection refused (os error 111)",
                true,
                Reach::Proxy,
            ),
            (
                "error sending request: client error (Connect): dns error: failed to lookup address information",
                true,
                Reach::Proxy,
            ),
            // libgit2's.
            (
                "failed to resolve address for nowhere.invalid: Name or service not known",
                false,
                Reach::Dns,
            ),
            (
                "failed to connect to 127.0.0.1: Connection refused",
                false,
                Reach::Unreachable,
            ),
            ("the SSL certificate is invalid", false, Reach::Tls),
            ("something nobody has seen", false, Reach::Other),
        ] {
            assert_eq!(classify(message, proxied).reach, reach, "{message}");
        }
    }

    #[test]
    fn a_line_names_the_host_and_not_the_url() {
        let url = "https://example.org/a/b?token=abc";
        assert_eq!(host_of(url).as_deref(), Some("example.org"));
        assert_eq!(
            scrubbed(&format!("failed for {url}: no"), url, "example.org"),
            "failed for example.org: no"
        );
        assert_eq!(host_of("not a url"), None);
    }

    fn a_reach() -> impl Strategy<Value = Reach> {
        prop_oneof![
            Just(Reach::Reached),
            Just(Reach::Dns),
            Just(Reach::Unreachable),
            Just(Reach::Tls),
            Just(Reach::Proxy),
            Just(Reach::Other),
        ]
    }

    proptest! {
        /// What the probe prints is read back as it was: up.nu parses it.
        #[test]
        fn a_line_reads_back_as_it_was_printed(
            agent in "[a-z-]{1,20}",
            host in "[a-z0-9.-]{1,30}",
            reach in a_reach(),
            detail in ".{0,80}",
        ) {
            let line = ProbeLine { agent, protocol: "git".to_string(), host, verdict: reach, detail };
            let text = serde_json::to_string(&line).unwrap();
            prop_assert!(!text.contains('\n'));
            prop_assert_eq!(serde_json::from_str::<ProbeLine>(&text).unwrap(), line);
        }

        /// A detail never carries the URL's path or query, wherever in it the URL appears.
        #[test]
        fn a_detail_never_carries_the_rest_of_the_url(
            host in "[a-z]{1,10}\\.[a-z]{2,5}",
            path in "/[a-z]{1,10}",
            query in "[a-z]{1,8}=[a-z0-9]{12,20}",
            before in "[ -~]{0,30}",
            after in "[ -~]{0,30}",
        ) {
            let url = format!("https://{host}{path}?{query}");
            let detail = scrubbed(&format!("{before}{url}{after}"), &url, &host);
            prop_assert!(!detail.contains(&query) || before.contains(&query) || after.contains(&query));
        }

        /// A verdict follows its rule for any message: a certificate is TLS whatever else is said, and through a proxy no
        /// failure to resolve or connect is put down to the destination.
        #[test]
        fn a_verdict_follows_its_order(
            message in "[ -~]{0,60}",
            word in prop::sample::select(vec!["certificate", "dns error", "connection refused", "unsuccessful tunnel"]),
            proxied in any::<bool>(),
        ) {
            let said = format!("{message}{word}");
            let reach = classify(&said, proxied).reach;
            let lower = said.to_ascii_lowercase();
            if TLS.iter().any(|w| lower.contains(w)) {
                prop_assert_eq!(reach, Reach::Tls);
            } else if proxied {
                prop_assert_eq!(reach, Reach::Proxy);
            } else {
                prop_assert!(matches!(reach, Reach::Dns | Reach::Unreachable | Reach::Proxy));
            }
        }
    }
}
