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

//! The canary's side of proving network enforcement (docs/plans/runtime-attestation/network-enforcement.md, the canary):
//! `build-fetch --probe-network`, run by the orchestrator in a pod made as a build's, under the builds' own policy. It
//! connects to each address the pod must reach, and to each it must not, and succeeds only when every one of the first
//! connects and none of the second does. Every address the orchestrator names here answers when it is reachable (the
//! registry, the Kubernetes API, an address outside that serves), so a connection that does not open, whether dropped,
//! refused or unroutable, is one the network did not let through.

use polar_env::{Config, Described, Optional, Required, Section};
use std::time::Duration;

/// The argument that runs the probe in place of a fetch.
pub const PROBE_ARG: &str = "--probe-network";
/// How long a connection has to open.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub static REACH: Required<String> = Required::text(
    "CYCLOPS_PROBE_REACH",
    "the addresses the pod must reach, `host:port`, comma-separated: the registry, which proves the pod's network works",
);
pub static UNREACHABLE: Optional<String> = Optional::text(
    "CYCLOPS_PROBE_UNREACHABLE",
    "the addresses the pod must not reach, `host:port`, comma-separated: each one that answers when it is reachable",
);

static VARIABLES: &[&dyn Described] = &[&REACH, &UNREACHABLE];

/// The section the probe reads.
pub static PROBE_SECTION: Section = Section {
    name: "build-fetch-probe",
    vars: VARIABLES,
    relations: |_| Vec::new(),
};

/// What one address did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub address: String,
    pub must_reach: bool,
    /// None when the connection opened; why it did not, otherwise.
    pub refused: Option<String>,
}

impl Seen {
    /// Whether this address did what it had to.
    pub fn as_required(&self) -> bool {
        self.must_reach == self.refused.is_none()
    }

    /// One line for the pod's log.
    pub fn line(&self) -> String {
        let verdict = if self.as_required() {
            "as required"
        } else {
            "NOT as required"
        };
        match (&self.refused, self.must_reach) {
            (None, true) => format!("{}: reached, {verdict}", self.address),
            (None, false) => format!("{}: reached, and must not be: {verdict}", self.address),
            (Some(why), true) => format!(
                "{}: not reached ({why}), and must be: {verdict}",
                self.address
            ),
            (Some(why), false) => format!("{}: not reached ({why}), {verdict}", self.address),
        }
    }
}

/// The comma-separated addresses of a setting, each trimmed, the empty ones left out.
pub fn addresses(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .collect()
}

/// Connects to every address, each within `timeout`, and says what each did.
pub async fn probe(reach: &[String], unreachable: &[String], timeout: Duration) -> Vec<Seen> {
    let mut seen = Vec::new();
    for (address, must_reach) in reach
        .iter()
        .map(|a| (a, true))
        .chain(unreachable.iter().map(|a| (a, false)))
    {
        let refused =
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address.as_str()))
                .await
            {
                Ok(Ok(_)) => None,
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => Some(format!("no answer within {}s", timeout.as_secs())),
            };
        seen.push(Seen {
            address: address.clone(),
            must_reach,
            refused,
        });
    }
    seen
}

/// The probe as the pod runs it: the addresses from its settings, every one probed, and success only when every one
/// did as required. An empty list of addresses to reach proves nothing, and fails.
pub async fn run(config: &Config) -> Result<Vec<Seen>, Vec<Seen>> {
    let reach = config
        .read(&REACH)
        .map(|r| addresses(&r))
        .unwrap_or_default();
    let unreachable = config
        .read(&UNREACHABLE)
        .ok()
        .flatten()
        .map(|u| addresses(&u))
        .unwrap_or_default();
    let seen = probe(&reach, &unreachable, PROBE_TIMEOUT).await;
    if !reach.is_empty() && seen.iter().all(Seen::as_required) {
        Ok(seen)
    } else {
        Err(seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An address on this machine that refuses: a port bound and closed again.
    async fn closed() -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap().to_string();
        drop(l);
        a
    }

    #[tokio::test]
    async fn an_address_that_answers_is_reached_and_one_that_refuses_is_not() {
        let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_addr = open.local_addr().unwrap().to_string();
        let shut = closed().await;
        let seen = probe(
            std::slice::from_ref(&open_addr),
            std::slice::from_ref(&shut),
            Duration::from_secs(2),
        )
        .await;
        assert!(seen.iter().all(Seen::as_required), "{seen:?}");
        let seen = probe(&[shut], &[open_addr], Duration::from_secs(2)).await;
        assert!(seen.iter().all(|s| !s.as_required()), "{seen:?}");
    }

    #[tokio::test]
    async fn an_address_that_does_not_answer_in_time_is_not_reached() {
        // A non-routable address of the documentation range: nothing answers there.
        let seen = probe(&[], &["192.0.2.1:443".into()], Duration::from_millis(200)).await;
        assert!(
            seen[0].refused.is_some() && seen[0].as_required(),
            "{seen:?}"
        );
    }

    #[test]
    fn every_line_says_whether_the_address_did_as_required() {
        let s = |must_reach, refused: Option<&str>| Seen {
            address: "a:1".into(),
            must_reach,
            refused: refused.map(str::to_string),
        };
        assert!(!s(true, None).line().contains("NOT"));
        assert!(s(false, None).line().contains("NOT as required"));
        assert!(s(true, Some("refused")).line().contains("NOT as required"));
        assert!(!s(false, Some("refused")).line().contains("NOT"));
    }

    #[test]
    fn addresses_are_read_from_a_comma_separated_list() {
        assert_eq!(
            addresses(" a:1, b:2 ,,"),
            vec!["a:1".to_string(), "b:2".to_string()]
        );
        assert!(addresses("").is_empty());
    }
}
