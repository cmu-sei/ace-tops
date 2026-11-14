/*
  ACE Tool

  Copyright 2026 Carnegie Mellon University.

  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
  FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
  EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
  MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
  TRADEMARK, OR COPYRIGHT INFRINGEMENT.

  Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
  for full terms.

  [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
  distribution.  Please see Copyright notice for non-US Government use and distribution.

  This Software includes and/or makes use of Third-Party Software each subject to its own license.

  DM26-0670
*/

//! What the store and the witness say to each other (docs/architecture/runtime-attestation.md, "The witness of the
//! store's logs"; record-store.md, "Bite 5"): C2SP tlog-witness's `add-checkpoint`, over Cassini. The store asks on
//! [`WITNESS_REQUESTS_TOPIC`] in an [`Envelope`], and the witness answers, with the same correlation id, on the store's
//! own topic, [`STORE_WITNESS_REPLIES_TOPIC`]. The witness reads no entries: a request carries the size the store
//! believes the witness holds, the consistency proof from it, and the new checkpoint, signed.

pub use polar::request_reply::Envelope;
use rkyv::{Archive, Deserialize, Serialize};

/// Where the store brings its checkpoints, and the witness subscribes.
pub const WITNESS_REQUESTS_TOPIC: &str = "attestation-witness-requests";

/// The store's reply topic. The store is the one log the witness serves, so the topic is named, as the instance
/// check's askers' are, and not a family over every workload.
pub const STORE_WITNESS_REPLIES_TOPIC: &str = "attestation-witness-replies.polar-git-server";

/// The witness reply topic of the workload `workload`.
pub fn witness_replies_topic(workload: &str) -> String {
    format!("attestation-witness-replies.{workload}")
}

/// The most hashes a consistency proof carries, as tlog-witness bounds it: a proof between two trees of up to 2^63
/// leaves is never longer.
pub const MAX_PROOF: usize = 63;

/// A checkpoint brought to be co-signed: tlog-witness's `add-checkpoint`.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct AddCheckpoint {
    /// The size of the checkpoint the store believes the witness last co-signed for this origin; 0 for none.
    pub old: u64,
    /// The consistency proof from `old` to the checkpoint's size; empty from 0.
    pub proof: Vec<[u8; 32]>,
    /// The checkpoint, as a signed note with the store's signature.
    pub checkpoint: String,
}

/// Why the witness co-signed nothing: tlog-witness's refusals, by what each says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum Refusal {
    /// 400: the request is not one the witness can judge: `old` beyond the checkpoint's size, a proof longer than
    /// [`MAX_PROOF`], or a checkpoint that is not one.
    Malformed,
    /// 403: no signature from the store's pinned key verifies, or that key's signature fails.
    Untrusted,
    /// 404: the checkpoint's origin is not under the pinned store's name, or no store is pinned.
    UnknownOrigin,
    /// 422: the checkpoint cannot follow what the witness co-signed: the proof fails, two roots for one size, a proof
    /// from size 0, or an empty tree whose root is not the empty one.
    Inconsistent,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refusal::Malformed => "the request is malformed",
            Refusal::Untrusted => "the checkpoint is not signed by the pinned store's key",
            Refusal::UnknownOrigin => "the origin is not one the witness serves",
            Refusal::Inconsistent => {
                "the checkpoint is not consistent with what the witness co-signed"
            }
        })
    }
}

/// What the witness did with a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum Answer {
    /// Kept, then co-signed: the co-signature line, to be appended to the note.
    Cosigned(String),
    /// 409: the request's `old` is not the size the witness holds for this origin, which is this.
    Conflict(u64),
    /// Nothing co-signed, and why.
    Refused(Refusal),
}

/// The witness's answer, naming the checkpoint it is about, as its note's text said (none when the witness could not
/// read one), so the store matches it to what it asked.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct Witnessed {
    pub origin: Option<String>,
    pub size: Option<u64>,
    pub answer: Answer,
}

/// The bytes of a request, as it is published.
pub fn encode_add_checkpoint(envelope: &Envelope<AddCheckpoint>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("a request of owned values always serializes")
        .into_vec()
}

/// The bytes of an answer, as it is published.
pub fn encode_witnessed(envelope: &Envelope<Witnessed>) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(envelope)
        .expect("an answer of owned values always serializes")
        .into_vec()
}

/// The request in `payload`, or why it is not one. The bytes are validated before anything is read from them.
pub fn decode_add_checkpoint(payload: &[u8]) -> Result<Envelope<AddCheckpoint>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<AddCheckpoint>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a checkpoint to witness: {e}"))
}

/// The answer in `payload`, or why it is not one. The bytes are validated before anything is read from them.
pub fn decode_witnessed(payload: &[u8]) -> Result<Envelope<Witnessed>, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<Envelope<Witnessed>, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a witness's answer: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn the_stores_topic_is_the_one_it_is_answered_on() {
        assert_eq!(
            witness_replies_topic("polar-git-server"),
            STORE_WITNESS_REPLIES_TOPIC
        );
    }

    #[test]
    fn each_refusal_says_what_it_is() {
        let said: std::collections::BTreeSet<String> = [
            Refusal::Malformed,
            Refusal::Untrusted,
            Refusal::UnknownOrigin,
            Refusal::Inconsistent,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(said.len(), 4);
    }

    fn a_request() -> impl Strategy<Value = Envelope<AddCheckpoint>> {
        (
            "[a-f0-9-]{0,36}",
            any::<u64>(),
            prop::collection::vec(any::<[u8; 32]>(), 0..=MAX_PROOF),
            "\\PC{0,200}",
        )
            .prop_map(|(correlation_id, old, proof, checkpoint)| Envelope {
                correlation_id,
                payload: AddCheckpoint {
                    old,
                    proof,
                    checkpoint,
                },
            })
    }

    fn a_refusal() -> impl Strategy<Value = Refusal> {
        prop_oneof![
            Just(Refusal::Malformed),
            Just(Refusal::Untrusted),
            Just(Refusal::UnknownOrigin),
            Just(Refusal::Inconsistent),
        ]
    }

    fn an_answer() -> impl Strategy<Value = Envelope<Witnessed>> {
        let answer = prop_oneof![
            "\\PC{0,120}".prop_map(Answer::Cosigned),
            any::<u64>().prop_map(Answer::Conflict),
            a_refusal().prop_map(Answer::Refused),
        ];
        (
            "[a-f0-9-]{0,36}",
            prop::option::of("[a-z0-9./-]{1,80}"),
            prop::option::of(any::<u64>()),
            answer,
        )
            .prop_map(|(correlation_id, origin, size, answer)| Envelope {
                correlation_id,
                payload: Witnessed {
                    origin,
                    size,
                    answer,
                },
            })
    }

    proptest! {
        #[test]
        fn a_request_reads_back_as_it_was_sent(request in a_request()) {
            let read = decode_add_checkpoint(&encode_add_checkpoint(&request)).unwrap();
            prop_assert_eq!(read.correlation_id, request.correlation_id);
            prop_assert_eq!(read.payload, request.payload);
        }

        #[test]
        fn an_answer_reads_back_as_it_was_sent(answer in an_answer()) {
            let read = decode_witnessed(&encode_witnessed(&answer)).unwrap();
            prop_assert_eq!(read.correlation_id, answer.correlation_id);
            prop_assert_eq!(read.payload, answer.payload);
        }

        /// Whatever arrives on a topic, reading it gives a value or a refusal, and never reads past the bytes.
        #[test]
        fn bytes_that_are_not_one_are_refused_not_read(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode_add_checkpoint(&bytes);
            let _ = decode_witnessed(&bytes);
        }
    }
}
