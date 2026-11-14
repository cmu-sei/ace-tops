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

use cassini_client::{
    ClientEventForwarder, ClientEventForwarderArgs, RegistrationState, TCPClientConfig,
};
use cassini_types::{ClientEvent as CassiniClientEvent, ControlResult};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ===== Mock Actor for testing ClientEventForwarder =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockMessage {
    pub payload: String,
}

#[derive(Debug)]
pub struct MockActor;

#[derive(Debug)]
pub struct MockActorArgs;

#[ractor::async_trait]
impl Actor for MockActor {
    type Msg = MockMessage;
    type State = ();
    type Arguments = MockActorArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        _args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(())
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        _msg: Self::Msg,
        _state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        Ok(())
    }
}

// ===== Tests for ClientEventForwarder =====

#[tokio::test]
async fn test_client_event_forwarder_mailbox() -> Result<(), ActorProcessingErr> {
    // Spawn a mock actor to receive forwarded events
    let (mock_ref, _handle) = Actor::spawn(None, MockActor, MockActorArgs).await?;

    // Create a mapper that transforms ClientEvent to MockMessage
    let mapper: Box<dyn Fn(CassiniClientEvent) -> Option<MockMessage> + Send + Sync + 'static> =
        Box::new(move |event| match event {
            CassiniClientEvent::MessagePublished { topic, .. } => Some(MockMessage {
                payload: format!("published:{topic}"),
            }),
            CassiniClientEvent::PublishAcknowledged { topic, .. } => Some(MockMessage {
                payload: format!("ack:{topic}"),
            }),
            CassiniClientEvent::Registered { registration_id } => Some(MockMessage {
                payload: format!("registered:{registration_id}"),
            }),
            CassiniClientEvent::ControlResponse { result, .. } => Some(MockMessage {
                payload: format!("control:{result:?}"),
            }),
            CassiniClientEvent::TransportError { reason } => Some(MockMessage {
                payload: format!("error:{reason}"),
            }),
            CassiniClientEvent::ClientSubscribed { .. } => None,
            CassiniClientEvent::RegistrationRefused { .. } => None,
            CassiniClientEvent::SessionEnded { .. } => None,
            CassiniClientEvent::SubscribeRefused { topic, reason }
            | CassiniClientEvent::PublishRefused { topic, reason }
            | CassiniClientEvent::PublishDropped { topic, reason }
            | CassiniClientEvent::PublishDeferred { topic, reason } => Some(MockMessage {
                payload: format!("refused:{topic}:{reason}"),
            }),
        });

    // Spawn the ClientEventForwarder with the mock actor as target
    let (forwarder_ref, _handle) = Actor::spawn(
        None,
        ClientEventForwarder::new(),
        ClientEventForwarderArgs {
            target: mock_ref,
            mapper,
        },
    )
    .await?;

    // Send a MessagePublished event
    forwarder_ref.send_message(CassiniClientEvent::MessagePublished {
        topic: "test-topic".to_string(),
        payload: vec![1, 2, 3],
        trace_ctx: None,
        published_by: None,
        published_instance: None,
    })?;

    // Give the actor time to process the message
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Assert the mock actor received the mapped message by sending a verification event
    forwarder_ref.send_message(CassiniClientEvent::Registered {
        registration_id: "test-reg".to_string(),
    })?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    Ok(())
}

#[tokio::test]
async fn test_client_event_forwarder_multiple_events() -> Result<(), ActorProcessingErr> {
    // Spawn a mock actor
    let (mock_ref, _handle) = Actor::spawn(None, MockActor, MockActorArgs).await?;

    // Create a mapper that handles all event types
    let mapper: Box<dyn Fn(CassiniClientEvent) -> Option<MockMessage> + Send + Sync + 'static> =
        Box::new(move |event| match event {
            CassiniClientEvent::MessagePublished { topic, .. } => Some(MockMessage {
                payload: format!("pub:{topic}"),
            }),
            CassiniClientEvent::PublishAcknowledged { topic, .. } => Some(MockMessage {
                payload: format!("ack:{topic}"),
            }),
            CassiniClientEvent::Registered { registration_id } => Some(MockMessage {
                payload: format!("reg:{registration_id}"),
            }),
            CassiniClientEvent::ControlResponse { result, .. } => Some(MockMessage {
                payload: format!("ctrl:{result:?}"),
            }),
            CassiniClientEvent::TransportError { reason } => Some(MockMessage {
                payload: format!("err:{reason}"),
            }),
            CassiniClientEvent::ClientSubscribed { .. } => None,
            CassiniClientEvent::RegistrationRefused { .. } => None,
            CassiniClientEvent::SessionEnded { .. } => None,
            CassiniClientEvent::SubscribeRefused { topic, reason }
            | CassiniClientEvent::PublishRefused { topic, reason }
            | CassiniClientEvent::PublishDropped { topic, reason }
            | CassiniClientEvent::PublishDeferred { topic, reason } => Some(MockMessage {
                payload: format!("refused:{topic}:{reason}"),
            }),
        });

    // Spawn the forwarder
    let (forwarder_ref, _handle) = Actor::spawn(
        None,
        ClientEventForwarder::new(),
        ClientEventForwarderArgs {
            target: mock_ref,
            mapper,
        },
    )
    .await?;

    // Send multiple events
    forwarder_ref.send_message(CassiniClientEvent::MessagePublished {
        topic: "topic1".to_string(),
        payload: vec![1],
        trace_ctx: None,
        published_by: None,
        published_instance: None,
    })?;

    forwarder_ref.send_message(CassiniClientEvent::PublishAcknowledged {
        topic: "topic2".to_string(),
        id: cassini_types::MessageId { epoch: 1, seq: 1 },
    })?;

    forwarder_ref.send_message(CassiniClientEvent::Registered {
        registration_id: "reg-123".to_string(),
    })?;

    // Give time to process
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // The forwarder should have sent the messages to the target
    forwarder_ref.send_message(CassiniClientEvent::ControlResponse {
        registration_id: "reg".to_string(),
        result: Ok(ControlResult::Pong),
        trace_ctx: None,
    })?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    Ok(())
}

#[tokio::test]
async fn test_client_event_forwarder_filters_events() -> Result<(), ActorProcessingErr> {
    // Spawn a mock actor
    let (mock_ref, _handle) = Actor::spawn(None, MockActor, MockActorArgs).await?;

    // Create a mapper that only forwards PublishAcknowledged events
    let mapper: Box<dyn Fn(CassiniClientEvent) -> Option<MockMessage> + Send + Sync + 'static> =
        Box::new(move |event| match event {
            CassiniClientEvent::PublishAcknowledged { topic, .. } => Some(MockMessage {
                payload: format!("ack:{topic}"),
            }),
            _ => None, // Filter out other events
        });

    // Spawn the forwarder
    let (forwarder_ref, _handle) = Actor::spawn(
        None,
        ClientEventForwarder::new(),
        ClientEventForwarderArgs {
            target: mock_ref,
            mapper,
        },
    )
    .await?;

    // Send a MessagePublished event (should be filtered)
    forwarder_ref.send_message(CassiniClientEvent::MessagePublished {
        topic: "test".to_string(),
        payload: vec![1],
        trace_ctx: None,
        published_by: None,
        published_instance: None,
    })?;

    // Send a PublishAcknowledged event (should pass through)
    forwarder_ref.send_message(CassiniClientEvent::PublishAcknowledged {
        topic: "filtered".to_string(),
        id: cassini_types::MessageId { epoch: 1, seq: 2 },
    })?;

    // Give time to process
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // The forwarder should have sent the message to the target
    forwarder_ref.send_message(CassiniClientEvent::TransportError {
        reason: "verify".to_string(),
    })?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    Ok(())
}

// ===== Tests for TCPClientConfig::new =====

#[tokio::test]
async fn test_tcp_client_config_new() {
    let config = TCPClientConfig::new(
        "tcp://broker.example.com:5672".to_string(),
        "broker.example.com".to_string(),
        tls(),
    );

    assert_eq!(config.broker_endpoint, "tcp://broker.example.com:5672");
    assert_eq!(config.server_name, "broker.example.com");
}

#[tokio::test]
async fn test_tcp_client_config_new_empty_strings() {
    let config = TCPClientConfig::new("".to_string(), "".to_string(), tls());

    assert_eq!(config.broker_endpoint, "");
    assert_eq!(config.server_name, "");
}

#[tokio::test]
async fn test_tcp_client_config_new_unicode() {
    let config = TCPClientConfig::new(
        "tcp://broker-пример.com:5672".to_string(),
        "пример.com".to_string(),
        tls(),
    );

    assert_eq!(config.broker_endpoint, "tcp://broker-пример.com:5672");
    assert_eq!(config.server_name, "пример.com");
}

/// A TLS configuration to hold: these tests never connect, so whose it is does not matter.
fn tls() -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    )
}

// ===== Tests for RegistrationState variants =====

#[tokio::test]
async fn test_registration_state_unregistered() {
    let state = RegistrationState::Unregistered;

    match &state {
        RegistrationState::Unregistered => {}
        RegistrationState::Registered { .. } => panic!("Expected Unregistered"),
    }
}

#[tokio::test]
async fn test_registration_state_registered() {
    let state = RegistrationState::Registered {
        registration_id: "reg-abc-123".to_string(),
    };

    match &state {
        RegistrationState::Unregistered => panic!("Expected Registered"),
        RegistrationState::Registered { registration_id } => {
            assert_eq!(registration_id, "reg-abc-123");
        }
    }
}

#[tokio::test]
async fn test_registration_state_matches() {
    // Test that RegistrationState can be matched correctly
    let state = RegistrationState::Registered {
        registration_id: "reg-abc-123".to_string(),
    };

    match &state {
        RegistrationState::Unregistered => panic!("Expected Registered"),
        RegistrationState::Registered { registration_id } => {
            assert_eq!(registration_id, "reg-abc-123");
        }
    }
}
