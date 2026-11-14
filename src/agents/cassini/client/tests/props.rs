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

use cassini_client::{RegistrationState, TCPClientConfig};
use proptest::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;

/// A TLS configuration to hold: these tests never connect, so whose it is does not matter.
fn tls() -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    )
}

// ===== Proptests for TCPClientConfig::new =====

proptest! {
    #[test]
    fn prop_tcp_client_config_stores_arbitrary_strings(
        endpoint in any::<String>(),
        server_name in any::<String>(),
    ) {
        let config = TCPClientConfig::new(endpoint.clone(), server_name.clone(), tls());
        prop_assert_eq!(&config.broker_endpoint, &endpoint);
        prop_assert_eq!(&config.server_name, &server_name);
    }

    #[test]
    fn prop_tcp_client_config_handles_unicode(
        endpoint in "\\PC*",
        server_name in "\\PC*",
    ) {
        let config = TCPClientConfig::new(endpoint.clone(), server_name.clone(), tls());
        prop_assert_eq!(&config.broker_endpoint, &endpoint);
        prop_assert_eq!(&config.server_name, &server_name);
    }
}

// ===== Proptests for RegistrationState =====

proptest! {
    #[test]
    fn prop_registration_state_registered_stores_id(
        registration_id in any::<String>(),
    ) {
        let state = RegistrationState::Registered {
            registration_id: registration_id.clone(),
        };
        match state {
            RegistrationState::Registered { registration_id: id } => {
                prop_assert_eq!(id, registration_id);
            }
            RegistrationState::Unregistered => prop_assert!(false, "Expected Registered"),
        }
    }
}

// ===== The outbox: a message leaves only on its own acknowledgement =====

/// What happens to an outbox: a message published (of so many bytes), or an acknowledgement of the message pushed
/// `nth` (counted from the first, so it may name one already acknowledged, one not yet pushed, or another epoch's).
#[derive(Debug, Clone)]
enum OutboxEvent {
    Push(usize),
    Ack { nth: usize, other_epoch: bool },
}

fn outbox_events() -> impl Strategy<Value = Vec<OutboxEvent>> {
    prop::collection::vec(
        prop_oneof![
            (0usize..64).prop_map(OutboxEvent::Push),
            (0usize..40, prop::bool::weighted(0.1))
                .prop_map(|(nth, other_epoch)| OutboxEvent::Ack { nth, other_epoch }),
        ],
        0..80,
    )
}

proptest! {
    /// For any interleaving of publishes and acknowledgements, in any order, repeated or of messages it never held:
    /// the outbox holds exactly the messages pushed whose own acknowledgement has not come, oldest first, numbered
    /// 1, 2, 3 in its epoch, and its bytes are theirs.
    #[test]
    fn no_message_leaves_the_outbox_before_its_own_acknowledgement(events in outbox_events()) {
        use cassini_client::outbox::{Outbox, OutboxLimits};
        use cassini_types::MessageId;
        use std::sync::Arc;
        let epoch = 11;
        let mut outbox = Outbox::new(epoch, OutboxLimits { messages: usize::MAX, bytes: usize::MAX });
        let mut pushed: Vec<(MessageId, usize)> = Vec::new();
        let mut acked: HashSet<MessageId> = HashSet::new();
        for event in events {
            match event {
                OutboxEvent::Push(len) => {
                    let id = outbox.push("t".into(), Arc::new(vec![0; len]), None, true).id;
                    prop_assert_eq!(id, MessageId { epoch, seq: pushed.len() as u64 + 1 });
                    pushed.push((id, len));
                }
                OutboxEvent::Ack { nth, other_epoch } => {
                    let id = MessageId {
                        epoch: if other_epoch { epoch + 1 } else { epoch },
                        seq: nth as u64 + 1,
                    };
                    let held = pushed.iter().any(|(p, _)| *p == id) && !acked.contains(&id);
                    prop_assert_eq!(outbox.settle(id).map(|e| e.id), held.then_some(id));
                    // An acknowledgement of a message not held (not yet numbered, or already let go) changes nothing.
                    if held {
                        acked.insert(id);
                    }
                }
            }
            let expected: Vec<(MessageId, usize)> =
                pushed.iter().filter(|(id, _)| !acked.contains(id)).cloned().collect();
            prop_assert_eq!(
                outbox.entries().map(|e| (e.id, e.payload.len())).collect::<Vec<_>>(),
                expected.clone()
            );
            prop_assert_eq!(outbox.bytes(), expected.iter().map(|(_, len)| len).sum::<usize>());
        }
    }
}
