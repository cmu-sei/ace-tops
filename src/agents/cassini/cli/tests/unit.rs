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

//! The command line's wire types and output (moved with the command line from cassini-client).

use cassini_cli::cli::{IpcRequest, IpcResponse, OutputFormat, print_control_result};
use cassini_types::{ControlResult, SessionDetails, SessionMap};
use std::collections::HashSet;

// ===== Tests for IpcRequest serde roundtrips =====

#[tokio::test]
async fn test_ipc_request_publish_roundtrip() {
    let original = IpcRequest::Publish {
        topic: "test-topic".to_string(),
        payload_b64: "SGVsbG8gV29ybGQ=".to_string(),
        timeout_secs: 30,
    };

    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&serialized).unwrap();

    match (original, deserialized) {
        (
            IpcRequest::Publish {
                topic,
                payload_b64,
                timeout_secs,
            },
            IpcRequest::Publish {
                topic: t,
                payload_b64: pb,
                timeout_secs: ts,
            },
        ) => {
            assert_eq!(topic, t);
            assert_eq!(payload_b64, pb);
            assert_eq!(timeout_secs, ts);
        }
        _ => panic!("Expected Publish variant"),
    }
}

#[tokio::test]
async fn test_ipc_request_list_sessions_roundtrip() {
    let original = IpcRequest::ListSessions { timeout_secs: 15 };

    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&serialized).unwrap();

    match (original, deserialized) {
        (
            IpcRequest::ListSessions { timeout_secs },
            IpcRequest::ListSessions { timeout_secs: ts },
        ) => {
            assert_eq!(timeout_secs, ts);
        }
        _ => panic!("Expected ListSessions variant"),
    }
}

#[tokio::test]
async fn test_ipc_request_get_session_roundtrip() {
    let original = IpcRequest::GetSession {
        registration_id: "reg-123".to_string(),
        timeout_secs: 45,
    };

    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&serialized).unwrap();

    match (original, deserialized) {
        (
            IpcRequest::GetSession {
                registration_id,
                timeout_secs,
            },
            IpcRequest::GetSession {
                registration_id: rid,
                timeout_secs: ts,
            },
        ) => {
            assert_eq!(registration_id, rid);
            assert_eq!(timeout_secs, ts);
        }
        _ => panic!("Expected GetSession variant"),
    }
}

#[tokio::test]
async fn test_ipc_request_status_roundtrip() {
    let original = IpcRequest::Status;

    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: IpcRequest = serde_json::from_str(&serialized).unwrap();

    match (original, deserialized) {
        (IpcRequest::Status, IpcRequest::Status) => {}
        _ => panic!("Expected Status variant"),
    }
}

// ===== Tests for IpcResponse serde roundtrips =====

#[tokio::test]
async fn test_ipc_response_ok_with_result_roundtrip() {
    let original = IpcResponse::Ok {
        result: Some(serde_json::json!({"status": "ok", "topic": "test"})),
    };

    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&serialized).unwrap();

    match (original, deserialized) {
        (IpcResponse::Ok { result: Some(val) }, IpcResponse::Ok { result: Some(val2) }) => {
            assert_eq!(val, val2);
        }
        _ => panic!("Expected Ok variant with Some result"),
    }
}

#[tokio::test]
async fn test_ipc_response_ok_without_result_roundtrip() {
    let original = IpcResponse::Ok { result: None };

    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&serialized).unwrap();

    match (original, deserialized) {
        (IpcResponse::Ok { result: None }, IpcResponse::Ok { result: None }) => {}
        _ => panic!("Expected Ok variant with None result"),
    }
}

#[tokio::test]
async fn test_ipc_response_error_roundtrip() {
    let original = IpcResponse::Error {
        reason: "Test error message".to_string(),
    };

    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: IpcResponse = serde_json::from_str(&serialized).unwrap();

    match (original, deserialized) {
        (IpcResponse::Error { reason }, IpcResponse::Error { reason: r }) => {
            assert_eq!(reason, r);
        }
        _ => panic!("Expected Error variant"),
    }
}

// ===== Tests for print_control_result =====

#[tokio::test]
async fn test_print_control_result_json_format() {
    let session_map: SessionMap = [(
        "reg-123".to_string(),
        SessionDetails {
            registration_id: "reg-123".to_string(),
            subscriptions: HashSet::new(),
        },
    )]
    .into_iter()
    .collect();
    let result = ControlResult::SessionList(session_map);
    let format = OutputFormat::Json;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_session_list() {
    let session_map: SessionMap = [(
        "reg-123".to_string(),
        SessionDetails {
            registration_id: "reg-123".to_string(),
            subscriptions: HashSet::new(),
        },
    )]
    .into_iter()
    .collect();
    let result = ControlResult::SessionList(session_map);
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_empty_session_list() {
    let result = ControlResult::SessionList(SessionMap::new());
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_topic_list() {
    let result = ControlResult::TopicList(HashSet::from([
        "topic1".to_string(),
        "topic2".to_string(),
        "topic3".to_string(),
    ]));
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_empty_topic_list() {
    let result = ControlResult::TopicList(HashSet::new());
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_session_info() {
    let result = ControlResult::SessionInfo(SessionDetails {
        registration_id: "reg-123".to_string(),
        subscriptions: HashSet::new(),
    });
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_subscriber_list() {
    let result =
        ControlResult::SubscriberList(vec!["subscriber1".to_string(), "subscriber2".to_string()]);
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_empty_subscriber_list() {
    let result = ControlResult::SubscriberList(vec![]);
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_pong() {
    let result = ControlResult::Pong;
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_disconnected() {
    let result = ControlResult::Disconnected;
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_text_format_shutdown_initiated() {
    let result = ControlResult::ShutdownInitiated;
    let format = OutputFormat::Text;

    // Should not panic and return Ok
    let res = print_control_result(&result, &format);
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_print_control_result_json_format_all_variants() {
    let variants = [
        ControlResult::SessionList(SessionMap::new()),
        ControlResult::TopicList(HashSet::new()),
        ControlResult::SessionInfo(SessionDetails {
            registration_id: "reg-123".to_string(),
            subscriptions: HashSet::new(),
        }),
        ControlResult::SubscriberList(vec![]),
        ControlResult::Pong,
        ControlResult::Disconnected,
        ControlResult::ShutdownInitiated,
    ];

    for result in variants {
        let format = OutputFormat::Json;
        // Should not panic and return Ok for all variants
        let res = print_control_result(&result, &format);
        assert!(res.is_ok(), "Failed for variant: {:?}", result);
    }
}
