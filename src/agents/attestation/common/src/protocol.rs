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

//! What askers and the attestation agent say to each other (docs/architecture/runtime-attestation.md, "Slice A"): a question in an
//! [`Envelope`] on [`REQUESTS_TOPIC`], and its [`Verdict`], with the same correlation id, on the asker's own reply topic
//! (docs/architecture/cassini-request-reply-protocol.md).

use crate::verdict::Verdict;
pub use polar::request_reply::Envelope;
use rkyv::{Archive, Deserialize, Serialize};

/// The attestation agent's workload name.
pub const AGENT_NAME: &str = "attestation-agent";

/// Where every asker publishes its questions, and the attestation agent subscribes.
pub const REQUESTS_TOPIC: &str = "attestation-instance-requests";

/// The family of reply topics, one for each asker.
pub const REPLIES_FAMILY: &str = "attestation-instance-replies.{workload}";

/// The reply topic of the workload `workload`.
pub fn replies_topic(workload: &str) -> String {
    REPLIES_FAMILY.replacen("{workload}", workload, 1)
}

/// Is the instance behind this token what the deployment made? It names what the token says: the identity it was issued for and the
/// pod UID it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct InstanceQuestion {
    pub identity: String,
    pub pod_uid: String,
}

/// The bytes of a question, as it is published.
pub fn encode_question(envelope: &Envelope<InstanceQuestion>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("a question of owned strings always serializes")
        .into_vec()
}

/// The bytes of a verdict, as it is published.
pub fn encode_verdict(envelope: &Envelope<Verdict>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("a verdict of owned strings always serializes")
        .into_vec()
}

/// The question in `payload`, or why it is not one. The bytes are validated before anything is read from them.
pub fn decode_question(payload: &[u8]) -> Result<Envelope<InstanceQuestion>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<InstanceQuestion>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not an instance question: {e}"))
}

/// The verdict in `payload`, or why it is not one. The bytes are validated before anything is read from them.
pub fn decode_verdict(payload: &[u8]) -> Result<Envelope<Verdict>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<Verdict>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a verdict: {e}"))
}
