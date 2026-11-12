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

//! What the credentials agent does with the instance check (docs/architecture/runtime-attestation.md, "Slice A, the askers"), for each way into
//! issuance: not genuine is a refusal, recorded; could not ask issues, and records that it did, so that what was signed unattested can be attested
//! afterwards. It is asked before the renewal rule, which records what it admits, so a refused pod has not used up its type.

use crate::issuance::call_append;
use crate::ledger::LedgerMessage;
use attestation_common::NotGenuine;
use attestation_common::asker::{Asked, InstanceAskerMessage, check};
use attestation_common::{Finding, accepted_report};
use credentials_agent_common::events::CredentialsEvent;
use ractor::ActorRef;
use tracing::{error, warn};

/// How a certificate may go ahead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admitted {
    Attested,
    /// Nothing could be learned about the pod, and why.
    Unattested(String),
}

/// Whether a certificate for `identity`, on the pod `pod_uid`, may go ahead. A refusal is recorded here.
pub async fn check_instance(
    asker: Option<&ActorRef<InstanceAskerMessage>>,
    ledger: &ActorRef<LedgerMessage>,
    path: &'static str,
    identity: &str,
    pod_uid: &str,
) -> Result<Admitted, NotGenuine> {
    match check(asker, path, identity, pod_uid).await {
        Asked::Genuine => Ok(Admitted::Attested),
        Asked::CouldNotAsk(why) => Ok(Admitted::Unattested(format!("{why:?}"))),
        Asked::NotGenuine(why) => {
            let event = CredentialsEvent::InstanceRefused {
                identity: identity.to_string(),
                instance_binding: pod_uid.to_string(),
                why: format!("{why:?}"),
                timestamp: polar::time::now_millis(),
            };
            if let Err(e) = call_append(ledger, event).await {
                error!("a refusal of a pod that is not genuine could not be recorded: {e}");
            }
            Err(why)
        }
    }
}

/// Records that a certificate went ahead unattested, if it did. `serial` is none where the signing is cert-issuer's to do afterwards: a held
/// request it was told to sign.
pub async fn record_if_unattested(
    admitted: &Admitted,
    ledger: &ActorRef<LedgerMessage>,
    identity: &str,
    pod_uid: &str,
    serial: Option<&str>,
) {
    let Admitted::Unattested(why) = admitted else {
        return;
    };
    let event = CredentialsEvent::IssuedUnattested {
        identity: identity.to_string(),
        instance_binding: pod_uid.to_string(),
        serial: serial.map(str::to_string),
        why: why.clone(),
        timestamp: polar::time::now_millis(),
    };
    if let Err(e) = call_append(ledger, event).await {
        error!(
            "a certificate issued without attestation could not be recorded, so it will not be attested afterwards -- genuine audit-trail gap, needs operator attention: {e}"
        );
    }
}

/// Takes something the attestation agent published on its reports topic, published (the broker says) by `published_by`: it is recorded once and logged,
/// and nothing else follows from it (docs/architecture/runtime-attestation.md, "Slice B"). Returns whether it was new.
pub async fn take_report(
    ledger: &ActorRef<LedgerMessage>,
    payload: &[u8],
    published_by: Option<&str>,
    agent: &str,
) -> bool {
    let report = match accepted_report(payload, published_by, agent) {
        Ok(report) => report,
        Err(why) => {
            warn!("not taken as a report: {why}");
            return false;
        }
    };
    let kind = match &report.finding {
        Finding::Altered(_) => "altered",
        Finding::Crashed { .. } => "crashed",
    };
    let finding = format!("{:?}", report.finding);
    let event = CredentialsEvent::AttestationReported {
        namespace: report.namespace.clone(),
        pod: report.pod.clone(),
        pod_uid: report.pod_uid.clone(),
        kind: kind.to_string(),
        finding: finding.clone(),
        timestamp: polar::time::now_millis(),
        under_test: report.under_test,
    };
    match ractor::call!(ledger, |reply| LedgerMessage::TakeAttestationReport {
        event,
        reply,
    }) {
        Ok(Ok(true)) => {
            if report.under_test {
                warn!(
                    namespace = report.namespace,
                    pod = report.pod,
                    pod_uid = report.pod_uid,
                    under_test = true,
                    "the attestation agent reports of a pod under test, to be looked at: {finding}"
                );
            } else {
                error!(
                    namespace = report.namespace,
                    pod = report.pod,
                    pod_uid = report.pod_uid,
                    "the attestation agent reports of a pod, to be looked at: {finding}"
                );
            }
            true
        }
        Ok(Ok(false)) => false,
        Ok(Err(e)) => {
            error!("a report of the attestation agent's could not be recorded: {e}");
            false
        }
        Err(e) => {
            error!("the ledger did not take a report of the attestation agent's: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation_common::{CrashSignal, NotGenuine, Report, encode_report};

    const AGENT: &str = "attestation-agent.polar.serviceaccount.cluster.local";

    fn crash() -> Report {
        Report {
            namespace: "polar".into(),
            pod: "jira-observer-abc".into(),
            pod_uid: "uid-1".into(),
            finding: Finding::Crashed {
                container: "jira-observer".into(),
                signal: CrashSignal::Segv,
                exit_code: 139,
                finished_at: "2026-11-03T12:00:00Z".into(),
                image_id: "registry/jira-observer@sha256:0".into(),
            },
            under_test: false,
        }
    }

    async fn ledger_at(path: &str) -> ActorRef<LedgerMessage> {
        crate::ledger::tests::spawn_ledger(path).await
    }

    #[tokio::test]
    async fn a_report_is_recorded_once_however_often_it_is_sent_and_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let path = path.to_str().unwrap();
        let ledger = ledger_at(path).await;
        let bytes = encode_report(&crash());
        assert!(take_report(&ledger, &bytes, Some(AGENT), AGENT).await);
        assert!(!take_report(&ledger, &bytes, Some(AGENT), AGENT).await);
        let events = crate::ledger::tests::events_in(path);
        assert_eq!(events.matches("AttestationReported").count(), 1, "{events}");
        assert!(events.contains("crashed"), "{events}");
        assert!(events.contains("Segv"), "{events}");

        // The ledger replays, so a restarted credentials agent still knows it.
        ledger.stop(None);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let again = ledger_at(path).await;
        assert!(!take_report(&again, &bytes, Some(AGENT), AGENT).await);
        let events = crate::ledger::tests::events_in(path);
        assert_eq!(events.matches("AttestationReported").count(), 1, "{events}");
    }

    #[tokio::test]
    async fn another_finding_about_the_same_pod_is_another_report() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let ledger = ledger_at(path.to_str().unwrap()).await;
        let mut altered = crash();
        altered.finding = Finding::Altered(NotGenuine::EphemeralContainer {
            container: "debugger".into(),
        });
        assert!(take_report(&ledger, &encode_report(&crash()), Some(AGENT), AGENT).await);
        assert!(take_report(&ledger, &encode_report(&altered), Some(AGENT), AGENT).await);
    }

    #[tokio::test]
    async fn only_the_attestation_agent_as_the_broker_stamped_it_is_believed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.log");
        let path = path.to_str().unwrap();
        let ledger = ledger_at(path).await;
        let bytes = encode_report(&crash());
        assert!(!take_report(&ledger, &bytes, Some("intruder"), AGENT).await);
        assert!(!take_report(&ledger, &bytes, None, AGENT).await);
        assert!(!take_report(&ledger, b"nonsense", Some(AGENT), AGENT).await);
        let events = crate::ledger::tests::events_in(path);
        assert!(!events.contains("AttestationReported"), "{events}");
    }
}
