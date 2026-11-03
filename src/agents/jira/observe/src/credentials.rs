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

//! The observer's `credentials` runtime section: the one credential it presents to the Jira site, bound to the hosts it
//! names (docs/architecture/jira.md, "The credential"). The builder judges each version and hands it to the CryptoActor, and
//! the handler asks for the credential for the site's host on each request and presents it, so nothing here ever has it
//! (docs/architecture/protocol-handlers.md). The entry is called `jira` ([`crate::CREDENTIAL`]): a `token` goes as `Bearer`
//! (a Data Center or Server personal access token), a `user-password` as Basic, the username the Cloud account's email and
//! the secret its API token. A new token is a new signed version: it reaches the running agent, and the observers start
//! again with it.

use polar_agent_builder::RuntimeSection;
use polar_agent_builder::protocol::credentials::section;

/// Most entries one version may carry: the observer reads one site.
pub const MAX_ENTRIES: usize = 1;

pub static CREDENTIALS: RuntimeSection = section::<MAX_ENTRIES>(
    "The credential the observer presents to the Jira site, an entry named jira, sent only to the hosts it names: a token \
     is a Data Center or Server personal access token, sent as Bearer; a user-password is a Jira Cloud API token with the \
     account's email as username, sent as Basic. Replaced whole by each version: a version with no entry withdraws it. \
     Not needed when JIRA_ANONYMOUS is true.",
);

/// The host a credential is asked for: the host of an `https` JIRA_URL, a name and not an address, with no login of
/// its own. A credential is never sent over a connection that is not encrypted (the git observer's rule,
/// `git_agent_common::remote::https_host`), so a site read with a credential must be https.
pub fn credential_host(jira_url: &str) -> Result<String, String> {
    let url = url::Url::parse(jira_url).map_err(|_| "JIRA_URL cannot be read".to_string())?;
    if url.scheme() != "https" {
        return Err(
            "JIRA_URL is not https, and a credential is sent only over https: set JIRA_URL to the site's https:// \
             address, or JIRA_ANONYMOUS to true to read it without one"
                .to_string(),
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("JIRA_URL carries a login of its own: take it out; the credential is the credentials section".to_string());
    }
    match url.host() {
        Some(url::Host::Domain(domain)) => Ok(domain.to_ascii_lowercase()),
        Some(_) => Err(
            "JIRA_URL names an address, and a credential is bound to a host name: set JIRA_URL to the site's name"
                .to_string(),
        ),
        None => Err("JIRA_URL has no host".to_string()),
    }
}

/// A real escrowed secret, for the tests of this crate.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_section_is_declared_soundly() {
        assert!(polar_agent_builder::runtime::check_declarations(&[&CREDENTIALS]).is_empty());
    }

    /// A credential goes only over https, to a host name, as git's do.
    #[test]
    fn the_credential_is_asked_for_the_host_of_an_https_address_only() {
        assert_eq!(
            credential_host("https://Jira.Example.org/jira").as_deref(),
            Ok("jira.example.org")
        );
        assert_eq!(
            credential_host("https://jira.example.org:8443").as_deref(),
            Ok("jira.example.org")
        );
        for (refused, why) in [
            ("http://jira.example.org", "https"),
            ("https://10.0.0.5", "address"),
            ("https://[::1]", "address"),
            ("https://me:pw@jira.example.org", "login"),
        ] {
            let error = credential_host(refused).unwrap_err();
            assert!(error.contains(why), "{refused}: {error}");
        }
    }
}
