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

//! An observer of something over HTTP, as a library (docs/architecture/http-observers.md). What to observe is a signed
//! runtime section, `sources`, so an endpoint is added without a deployment. Each kind is a small crate that gives its
//! name, its topic and its operation, so each is a workload with an identity of its own: not one observer that holds
//! everything, because the provenance chain has to be able to say which service was compromised and what it could touch.
//!
//! The observer schedules, fetches and publishes, and does not read what it fetched: only the processor parses what a
//! service sent, and an observer never touches the graph.

#![deny(clippy::disallowed_methods)]

pub mod observer;
pub mod sources;

pub use observer::{Kind, start};
pub use sources::{SOURCES, Source};

use rkyv::{Archive, Deserialize, Serialize};

/// The largest document that can be published. Cassini's frame is smaller than what the handler will read.
pub const MAX_DOCUMENT_BYTES: usize = cassini_types::MAX_PAYLOAD_BYTES - 4096;

/// What an observer publishes: a document, whose source it is, and when it was read.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct Observation {
    /// The source's name, as the signed section gives it.
    pub source: String,
    pub observed_at_unix_secs: i64,
    /// The document as it came.
    pub body: Vec<u8>,
}

impl Observation {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|bytes| bytes.to_vec())
            .map_err(|e| e.to_string())
    }

    pub fn decode(payload: &[u8]) -> Result<Observation, String> {
        // Copied to where rkyv wants it: a payload's alignment is whatever the transport left it.
        let mut aligned = rkyv::util::AlignedVec::<16>::new();
        aligned.extend_from_slice(payload);
        rkyv::from_bytes::<Observation, rkyv::rancor::Error>(&aligned).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn an_observation_comes_back_as_it_went(
            source in "[ -~]{0,16}", at in any::<i64>(), body in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            let sent = Observation { source, observed_at_unix_secs: at, body };
            prop_assert_eq!(Observation::decode(&sent.encode().unwrap()).unwrap(), sent);
        }

        #[test]
        fn what_is_not_an_observation_is_refused_and_does_not_panic(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = Observation::decode(&bytes);
        }
    }
}
