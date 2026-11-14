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

//! A workload's crypto actor asking for a key it keeps for one purpose to be certified (credentials-agent-common's
//! `key_certification`; docs/plans/record-store/to-main.md): a log's checkpoint key. Certified only for a workload the
//! authority model puts in the purpose's group (`checkpoints`), which its build gave it, judged by the broker-stamped
//! identity of whoever asks; signed by cert-issuer as that purpose's certificate alone, naming the workload and nothing
//! else. cert-issuer reports what it signs to the ledger (`credentials.certificates-reported`), so the certificate is
//! on the record as every other is.

use crate::supervisor::BROKER_CLIENT_NAME;
use cassini_client::TcpClientMessage;
use cert_client::handshake::HandshakeClient;
use cert_issuer_common::{CertType, InternalIssueRequest};
use credentials_agent_common::CREDENTIALS_KEY_CERTIFICATION_REPLIES_TOPIC;
use credentials_agent_common::key_certification::{
    CHECKPOINTS_GROUP, KeyCertificationRefusal, KeyCertificationReply, KeyCertificationRequest,
    KeyPurpose,
};
use polar::request_reply::Envelope;
use ractor::registry::where_is;
use ractor::{Actor, ActorProcessingErr, ActorRef, async_trait};
use std::sync::Arc;
use tracing::{error, info, warn};

/// The group a workload must be in for a key of `purpose` to be certified, and the certificate it gets.
fn purpose_of(purpose: KeyPurpose) -> (&'static str, CertType) {
    match purpose {
        KeyPurpose::Checkpoint => (CHECKPOINTS_GROUP, CertType::Checkpoint),
    }
}

/// Whether the model puts the workload `identity` in `group`.
pub(crate) fn in_group(
    model: Option<&credentials_agent_model::Model>,
    identity: &str,
    group: &str,
) -> bool {
    model.is_some_and(|model| {
        model
            .workloads
            .iter()
            .any(|w| w.identity == identity && w.groups.iter().any(|g| g == group))
    })
}

pub struct KeyCertificationHandler {
    /// cert-issuer, reached with this agent's own certificate, for `/internal/issue`.
    pub cert_issuer: HandshakeClient,
    pub authority_model: Option<Arc<credentials_agent_model::Model>>,
}

impl KeyCertificationHandler {
    /// The answer to `request`, from `requested_by`, the identity the broker stamped on it.
    pub async fn handle(
        &self,
        request: KeyCertificationRequest,
        requested_by: Option<String>,
    ) -> KeyCertificationReply {
        let refused = |reason| KeyCertificationReply::Refused { reason };
        let (group, cert_type) = purpose_of(request.purpose);
        let Some(identity) = requested_by else {
            warn!("a key certification request with no stamped identity: refused");
            return refused(KeyCertificationRefusal::NotPermitted);
        };
        if !in_group(self.authority_model.as_deref(), &identity, group) {
            warn!(%identity, ?request.purpose, "refused a key's certificate: the model does not put the workload in {group}");
            return refused(KeyCertificationRefusal::NotPermitted);
        }
        match self
            .cert_issuer
            .issue_internal(InternalIssueRequest {
                csr_pem: request.csr_pem,
                identity: identity.clone(),
                cert_type,
                extra_sans: Vec::new(),
                subject_dn_defaults: None,
                account_subject: None,
                instance_binding: None,
                expires_by: None,
            })
            .await
        {
            Ok(issued) => {
                info!(%identity, ?request.purpose, serial = %issued.serial_number, "certified a workload's key");
                KeyCertificationReply::Certified {
                    certificate_pem: issued.certificate_pem,
                    ca_chain_pem: issued.ca_chain_pem,
                    expires_at: issued.expires_at.unix_timestamp(),
                }
            }
            Err(e) => {
                error!(%identity, "cert-issuer did not certify a workload's key: {e}");
                refused(KeyCertificationRefusal::SigningFailed)
            }
        }
    }
}

/// Wraps the handler in its own actor, as the custodian's issuance is: the dispatch is synchronous, and cert-issuer is
/// not.
pub struct KeyCertificationActor;

/// The envelope, bundled with the broker-verified published_by.
pub struct KeyCertificationDispatch {
    pub envelope: Envelope<KeyCertificationRequest>,
    pub published_by: Option<String>,
}

#[async_trait]
impl Actor for KeyCertificationActor {
    type Msg = KeyCertificationDispatch;
    type State = KeyCertificationHandler;
    type Arguments = KeyCertificationHandler;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        handler: KeyCertificationHandler,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(handler)
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        handler: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        let envelope = Envelope {
            correlation_id: message.envelope.correlation_id.clone(),
            payload: handler
                .handle(message.envelope.payload, message.published_by)
                .await,
        };
        let payload = match rkyv::to_bytes::<rkyv::rancor::Error>(&envelope) {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                error!("Failed to serialize a key certification reply: {e}");
                return Ok(());
            }
        };
        match where_is(BROKER_CLIENT_NAME.to_string()) {
            Some(client) => {
                if let Err(e) = client.send_message(TcpClientMessage::publish(
                    CREDENTIALS_KEY_CERTIFICATION_REPLIES_TOPIC.to_string(),
                    payload,
                    None,
                )) {
                    error!("Failed to publish a key certification reply: {e}");
                }
            }
            None => error!("Broker client not found while publishing a key certification reply"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuance::tests::fake_issue_response;
    use proptest::prelude::*;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const STORE: &str = "polar-git-server.polar.serviceaccount.cluster.local";
    const OTHER: &str = "kube-consumer.polar.serviceaccount.cluster.local";

    /// A model with the store in `store_groups` and another workload in `other_groups`.
    fn model(store_groups: &[&str], other_groups: &[&str]) -> Arc<credentials_agent_model::Model> {
        let workload = |name: &str, identity: &str, groups: &[&str]| {
            serde_json::json!({
                "workload": name, "identity": identity, "issuer": "credentials-agent", "bootstrap": false,
                "groups": groups, "topics": []
            })
        };
        Arc::new(
            credentials_agent_model::Model::parse(
                &serde_json::json!({"format": 1, "workloads": [
                    workload("polar-git-server", STORE, store_groups),
                    workload("kube-consumer", OTHER, other_groups),
                ]})
                .to_string(),
            )
            .unwrap(),
        )
    }

    /// A cert-issuer that signs a checkpoint certificate for `identity` naming nothing else, for no pod; anything else
    /// it is asked is not mocked, and fails.
    async fn cert_issuer_certifying(identity: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internal/issue"))
            .and(body_partial_json(serde_json::json!({
                "identity": identity,
                "cert_type": "CHECKPOINT",
                "extra_sans": [],
                "instance_binding": null,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(fake_issue_response()))
            .mount(&server)
            .await;
        server
    }

    fn handler(
        server: &MockServer,
        model: Option<Arc<credentials_agent_model::Model>>,
    ) -> KeyCertificationHandler {
        KeyCertificationHandler {
            cert_issuer: HandshakeClient::new(server.uri()),
            authority_model: model,
        }
    }

    fn request() -> KeyCertificationRequest {
        KeyCertificationRequest {
            csr_pem: "a CSR".to_string(),
            purpose: KeyPurpose::Checkpoint,
        }
    }

    #[tokio::test]
    async fn a_workload_in_the_checkpoints_group_has_its_key_certified_for_checkpoints() {
        let server = cert_issuer_certifying(STORE).await;
        let reply = handler(&server, Some(model(&[CHECKPOINTS_GROUP], &[])))
            .handle(request(), Some(STORE.to_string()))
            .await;
        assert!(
            matches!(reply, KeyCertificationReply::Certified { .. }),
            "{reply:?}"
        );
    }

    /// Who may have a key certified is the stamped identity's workload, as the model groups it: not a workload outside
    /// the group, not an asker with no stamp, not one the model does not know, and nothing at all with no model.
    /// cert-issuer is never asked for any of them.
    #[tokio::test]
    async fn a_key_is_certified_for_no_one_else() {
        let server = MockServer::start().await;
        let grouped = Some(model(&[CHECKPOINTS_GROUP], &["encryption"]));
        for (what, model, asker) in [
            ("a workload outside the group", grouped.clone(), Some(OTHER)),
            ("no stamped identity", grouped.clone(), None),
            (
                "an identity the model does not know",
                grouped.clone(),
                Some("stranger"),
            ),
            ("no model", None, Some(STORE)),
        ] {
            let reply = handler(&server, model)
                .handle(request(), asker.map(str::to_string))
                .await;
            assert_eq!(
                reply,
                KeyCertificationReply::Refused {
                    reason: KeyCertificationRefusal::NotPermitted
                },
                "{what}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_key_cert_issuer_does_not_sign_is_refused_as_not_signed() {
        let server = MockServer::start().await;
        let reply = handler(&server, Some(model(&[CHECKPOINTS_GROUP], &[])))
            .handle(request(), Some(STORE.to_string()))
            .await;
        assert_eq!(
            reply,
            KeyCertificationReply::Refused {
                reason: KeyCertificationRefusal::SigningFailed
            }
        );
    }

    proptest! {
        /// The model puts a workload in a group exactly when its own entry names it: another's entry never counts.
        #[test]
        fn a_workload_is_in_a_group_exactly_when_its_own_entry_names_it(
            store_has in any::<bool>(),
            other_has in any::<bool>(),
        ) {
            let groups = |has: bool| if has { vec![CHECKPOINTS_GROUP] } else { vec!["encryption"] };
            let model = model(&groups(store_has), &groups(other_has));
            prop_assert_eq!(in_group(Some(&model), STORE, CHECKPOINTS_GROUP), store_has);
            prop_assert_eq!(in_group(Some(&model), OTHER, CHECKPOINTS_GROUP), other_has);
        }
    }
}
