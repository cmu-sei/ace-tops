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

//! What the Jira observer is, as the infrastructure asks to be told: see
//! `polar_agent_builder::PolarAgent`.

use crate::JiraDeployment;
use crate::settings::{self, JiraSettings};
use crate::supervisor::{
    Infrastructure, ObserverSupervisor, ObserverSupervisorArgs, SHUTDOWN_BUDGET,
};
use polar_agent_builder::held::Retry;
use polar_agent_builder::{
    Cause, Configured, GraphDecl, HoldReason, PolarAgent, Role, StartError, TopicDecl,
};
use polar_env::Section;
use ractor::Actor;
use std::time::Duration;
use tracing::info;

const JIRA_OBSERVER_SUPERVISOR: &str = "jira.supervisor.observer";

pub struct JiraObserver;

/// What the observers are started with, made from the configuration. The credential is not here: it is the signed
/// `credentials` runtime section, which the supervisor hands to the CryptoActor (`crate::credentials`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub jira_url: String,
    /// Read without a credential (JIRA_ANONYMOUS).
    pub anonymous: bool,
    pub deployment: JiraDeployment,
    pub query_date: Option<String>,
    /// Between two pulls.
    pub poll_secs: u64,
    /// How many items one request asks for.
    pub page_size: usize,
}

/// The observers' settings from `config`, or why they cannot work: an address that cannot be the site's (the
/// placeholder; one that is not https for a credential), or any other configuration error. Never a secret's value:
/// polar-env never shows one.
pub fn prepare(config: &polar_env::Config) -> Result<Prepared, String> {
    // Declared and judged with the rest of the configuration, so a missing address was reported before this point,
    // with every other problem.
    let settings = JiraSettings::read(config).map_err(|e| e.to_string())?;
    // An address that cannot be the site's is a configuration error, with what to set; so are a deployment that is
    // not one and a QUERY_DATE that is not a date.
    let jira_url = settings::normalise_jira_url(&settings.url)?;
    let deployment = settings
        .deployment
        .as_deref()
        .map(settings::parse_deployment)
        .transpose()?;
    let query_date = settings
        .query_date
        .as_deref()
        .filter(|date| !date.trim().is_empty())
        .map(settings::parse_query_date)
        .transpose()?
        .map(|date| date.to_string());
    // A credential goes only to the host of an https address, a name: said at once, with what to set.
    if !settings.anonymous {
        crate::credentials::credential_host(&jira_url)?;
    }
    Ok(Prepared {
        anonymous: settings.anonymous,
        deployment: JiraDeployment::resolve(deployment, &jira_url),
        jira_url,
        query_date,
        poll_secs: settings.poll_secs,
        page_size: settings.page_size,
    })
}

/// Whether settings can work, as [`prepare`] says: an update that would stop them working is refused.
fn settings_work(config: &polar_env::Config) -> Result<(), String> {
    prepare(config).map(|_| ())
}

/// What the start log says of reading anonymously.
pub(crate) fn log_anonymous(prepared: &Prepared) {
    if prepared.anonymous {
        info!(
            "JIRA_ANONYMOUS is true: the observer sends no credential and reads only what the site shows the public \
             (anonymous users); what it hides from them is not read. The users observer is not started: a Data Center \
             lists users only to a login (an anonymous user search is refused, 401)"
        );
    }
}

/// The way out of a hold at start: the settings made again from the configuration in force, and, if they work, the
/// supervisor started on the infrastructure the held agent built, linked under it.
fn try_again(
    retry: Retry,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> {
    Box::pin(async move {
        let prepared = prepare(&retry.config)?;
        log_anonymous(&prepared);
        Actor::spawn_linked(
            Some(JIRA_OBSERVER_SUPERVISOR.to_string()),
            ObserverSupervisor,
            ObserverSupervisorArgs {
                infrastructure: Infrastructure::Built {
                    resources: retry.resources,
                    registered: retry.cassini_registered,
                },
            },
            retry.supervisor,
        )
        .await
        .map(|_| ())
        .map_err(|e| {
            format!("the settings work now, but {JIRA_OBSERVER_SUPERVISOR} did not start: {e}")
        })
    })
}

impl PolarAgent for JiraObserver {
    const NAME: &'static str = crate::BROKER_CLIENT_NAME;
    const ROLE: Role = Role::Observer;
    const PURPOSE: &'static str =
        "Polls a Jira site for projects, groups, users and issues and publishes them to Cassini";
    const NEEDS: &'static [polar_agent_builder::Capability] = &[];
    // The CryptoActor holds the credential of the `credentials` runtime section, and the handler asks it for the site's
    // host only.
    const CREDENTIALS: Option<&'static polar_agent_builder::RuntimeSection> =
        Some(&crate::credentials::CREDENTIALS);
    const OPERATIONS: &'static [polar_agent_builder::protocol::OperationDecl] = crate::OPERATIONS;
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    // The infrastructure waits for it to finish its observers, stopped in turn.
    const HAS_OWN_DRAIN: bool = true;
    const SETTINGS_JUDGE: Option<polar_agent_builder::configuration::SettingsJudge> =
        Some(settings_work);
    const TOPICS: &'static [TopicDecl] = &[
        TopicDecl::publish(
            jira_common::JIRA_PROJECTS_CONSUMER_TOPIC,
            "the projects it reads from Jira",
        )
        .because(&[Cause::Timer("poll")]),
        TopicDecl::publish(
            jira_common::JIRA_GROUPS_CONSUMER_TOPIC,
            "the groups it reads from Jira",
        )
        .because(&[Cause::Timer("poll")]),
        TopicDecl::publish(
            jira_common::JIRA_USERS_CONSUMER_TOPIC,
            "the users it reads from Jira",
        )
        .because(&[Cause::Timer("poll")]),
        TopicDecl::publish(
            jira_common::JIRA_ISSUES_CONSUMER_TOPIC,
            "the issues it reads from Jira",
        )
        .because(&[Cause::Timer("poll")]),
    ];
    // Where its first issue pull starts: the newest update of an issue in the graph, asked of the state agent through
    // its state actor (docs/architecture/soft-state.md, "The Jira cursor"). The read gives it the soft-state
    // capability, and with it its request and reply topics.
    const GRAPH: &'static [GraphDecl] = &[GraphDecl::reads(
        crate::issues::CURSOR_LABEL,
        "the newest updated_ms of an issue, where its first issue pull starts",
    )];
    const SECTIONS: &'static [&'static Section] = &[&settings::SECTION];
    const HELP: Option<&'static str> = Some(
        "jira-observer polls the Jira site at JIRA_URL every half hour and publishes its \
         projects, groups, users and issues for jira-processor to write into the graph. \
         The credential comes in the `credentials` runtime section, as ciphertext only this agent can open, \
         used only for the hosts it is bound to: a `token` (a Data Center or Server personal access token) is \
         sent as Bearer, a `user-password` (a Jira Cloud account's email and API token) as Basic. \
         JIRA_ANONYMOUS=true reads without a credential, only what the site shows the public. The site's \
         serverInfo says whether it is Cloud; JIRA_DEPLOYMENT is used where it does not say, and the \
         address where neither does. Before its first issue pull it asks the state agent for the newest update of an \
         issue in the graph and starts there; QUERY_DATE starts the first pull from a date only when the graph \
         has no issue. The egress \
         section says how the site is reached: through POLAR_EGRESS_PROXY unless the host is in \
         POLAR_EGRESS_NO_PROXY, trusting the CA certificates of POLAR_EGRESS_CA_CERT beside the \
         system's (the CA of a TLS-intercepting proxy).",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging(JIRA_OBSERVER_SUPERVISOR);

        // A configuration that cannot work (the placeholder address) is not fixed by starting again: the agent stays
        // up with its infrastructure only, says why when it is asked about its health, and starts no observer
        // (docs/architecture/soft-state.md, "As built: pulled health"). A signed update that mends it starts them.
        let prepared = match prepare(configured.config()) {
            Ok(prepared) => prepared,
            Err(why) => {
                return polar_agent_builder::held::stay_up(
                    configured,
                    crate::BROKER_CLIENT_NAME,
                    HoldReason::Configuration,
                    why,
                    Box::new(try_again),
                )
                .await;
            }
        };
        log_anonymous(&prepared);
        let args = ObserverSupervisorArgs {
            infrastructure: Infrastructure::Build(configured),
        };

        let (_, handle) = Actor::spawn(
            Some(JIRA_OBSERVER_SUPERVISOR.to_string()),
            ObserverSupervisor,
            args,
        )
        .await
        .map_err(|e| format!("failed to start {JIRA_OBSERVER_SUPERVISOR}: {e}"))?;

        handle
            .await
            .map_err(|e| format!("{JIRA_OBSERVER_SUPERVISOR} task failed: {e}"))?;

        // The supervisor stopping is never a success: this agent's pod restarts on an exit, and only a
        // non-zero exit gets it restarted. `run` exits non-zero.
        Err(format!("{JIRA_OBSERVER_SUPERVISOR} stopped").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(JiraObserver);

    /// It only reads the graph, so it makes no constraint: only an owner does.
    #[test]
    fn a_reader_makes_no_constraint() {
        assert!(polar_agent_builder::agent::graph_key_indexes::<JiraObserver>().is_empty());
    }

    fn config(url: &str) -> polar_env::Config {
        config_of(&[("JIRA_URL", url)])
    }

    fn config_of(pairs: &[(&str, &str)]) -> polar_env::Config {
        let env: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        polar_env::Config::builder(&env)
            .register(&settings::SECTION)
            .register(&polar::egress::SECTION)
            .build()
    }

    /// The placeholder address is a configuration problem the agent holds, and says, rather than a reason to end.
    #[test]
    fn the_placeholder_address_is_a_configuration_problem_with_what_to_set() {
        let why = match prepare(&config("https://example.atlassian.net")) {
            Ok(_) => panic!("the placeholder was taken"),
            Err(why) => why,
        };
        assert!(why.contains("example placeholder"), "{why}");
        assert!(why.contains("workloads.jira-observer.env"), "{why}");
        let prepared = prepare(&config("https://jira.example.org")).unwrap();
        assert_eq!(prepared.jira_url, "https://jira.example.org");
    }

    /// What the agent says of settings is what refuses an update: the placeholder, and a credential over http.
    #[test]
    fn the_judge_refuses_what_prepare_refuses() {
        let judge = <JiraObserver as PolarAgent>::SETTINGS_JUDGE.expect("a judge");
        assert!(judge(&config("https://jira.example.org")).is_ok());
        assert!(
            judge(&config("https://example.atlassian.net"))
                .unwrap_err()
                .contains("placeholder")
        );
        assert!(
            judge(&config("http://jira.example.org"))
                .unwrap_err()
                .contains("https")
        );
    }

    /// A site read with a credential is https and a host name; one read anonymously needs neither.
    #[test]
    fn a_credential_goes_only_over_https() {
        let prepared = prepare(&config("https://Jira.Example.org/jira")).unwrap();
        assert!(!prepared.anonymous);

        let why = match prepare(&config("http://jira.example.org")) {
            Ok(_) => panic!("a credential would go over http"),
            Err(why) => why,
        };
        assert!(
            why.contains("https") && why.contains("JIRA_ANONYMOUS"),
            "{why}"
        );

        let anonymous = prepare(&config_of(&[
            ("JIRA_URL", "http://jira.example.org"),
            ("JIRA_ANONYMOUS", "true"),
        ]))
        .unwrap();
        assert!(anonymous.anonymous);
    }

    /// u7c's settings (infra/targets/sandbox-local/config.nuon): Apache's Jira, read anonymously as a Server, the
    /// first pull of an empty graph from 2026-10-31. They start the observers.
    #[test]
    fn u7c_s_settings_for_apache_s_jira_start_the_observers() {
        let prepared = prepare(&config_of(&[
            ("JIRA_URL", "https://issues.apache.org/jira"),
            ("JIRA_ANONYMOUS", "true"),
            ("JIRA_DEPLOYMENT", "server"),
            ("QUERY_DATE", "2026-10-31"),
        ]))
        .unwrap();
        assert_eq!(prepared.jira_url, "https://issues.apache.org/jira");
        assert!(prepared.anonymous);
        assert_eq!(prepared.deployment, JiraDeployment::ServerOrDataCenter);
        assert_eq!(prepared.query_date.as_deref(), Some("2026-10-31"));
    }

    /// The credential is the `credentials` runtime section, opened by the CryptoActor: declaring it brings encryption and
    /// the section, and the scaffold says what the agent asks of the site and with what.
    #[test]
    fn the_scaffold_says_the_agent_needs_encryption_and_reads_its_site_with_its_credential() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<JiraObserver>();
        assert!(scaffold.requires.contains(&"encryption".to_string()));
        assert!(
            scaffold
                .runtime
                .iter()
                .any(|section| section.name == "credentials")
        );
        let operations: Vec<(&str, Option<&str>, Option<&str>)> = scaffold
            .operations
            .iter()
            .map(|o| {
                (
                    o.name.as_str(),
                    o.variable.as_deref(),
                    o.credential.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            operations,
            [
                ("jira.site.read", Some("JIRA_URL"), Some("jira")),
                ("jira.site.read-anonymously", Some("JIRA_URL"), None),
            ]
        );
    }

    /// The render writes the target's egress setting only into an agent that declares the section.
    #[test]
    fn the_scaffold_declares_the_egress_section() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<JiraObserver>();
        let egress = scaffold
            .document
            .sections
            .iter()
            .find(|s| s.name == "egress")
            .expect("an egress section");
        let names: Vec<&str> = egress.variables.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "POLAR_EGRESS_PROXY",
                "POLAR_EGRESS_NO_PROXY",
                "POLAR_EGRESS_CA_CERT",
                "POLAR_EGRESS_CLUSTER_CA"
            ]
        );
        assert!(
            scaffold
                .document
                .sections
                .iter()
                .flat_map(|s| &s.variables)
                .all(|v| v.name != "PROXY_CA_CERT"),
            "PROXY_CA_CERT is gone"
        );
    }
}
