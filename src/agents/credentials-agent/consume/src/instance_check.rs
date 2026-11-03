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
use credentials_agent_common::events::CredentialsEvent;
use ractor::ActorRef;
use tracing::error;

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
