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

//! Whether a deployment record is to be believed (docs/architecture/runtime-attestation.md, "What the images are checked against").
//! It reaches this agent through the configuration agent, which is not trusted with it. So it is checked here: signed for this purpose,
//! by the pipeline, under the deployment CA. That CA is trusted for this and nothing else, so the deployment PKI gains no authority over
//! anything else in Polar.

use attestation_common::DeploymentRecord;
use polar_signing::{Document, Domain, Trust, verify_in};
use serde_json::Value;

/// The one identity of the deployment PKI that signs a record (`deploy-repo.nu`'s `WRITER`). Flux's certificate is under the same CA.
const SIGNER: &str = "pipeline";

/// The record in `text`, if it is to be believed at `now`.
pub fn read_record(text: &[u8], trust: &Trust, now: i64) -> Result<DeploymentRecord, String> {
    let value: Value =
        serde_json::from_slice(text).map_err(|e| format!("it is not a document: {e}"))?;
    let document =
        Document::from_value(&value).map_err(|e| format!("it is not a document: {e}"))?;
    let signer = verify_in(Domain::DEPLOYMENT_RECORD, &document, trust, now)
        .map_err(|e| format!("its signature is not believed: {e}"))?;
    if signer.identity.as_deref() != Some(SIGNER) {
        return Err(format!(
            "it is signed by {:?}, not {SIGNER}",
            signer.identity.as_deref().unwrap_or("no one named")
        ));
    }
    DeploymentRecord::from_payload(&document.payload)
}

/// What to do with a believed record, given the version held.
#[derive(Debug, PartialEq, Eq)]
pub enum Arrival {
    /// A later one: it replaces what is held.
    Newer,
    /// The one held: the configuration agent sends it again and again, for an agent that has just started.
    Same,
    /// An older one, which someone could only send on purpose: refused, or a pin could be rolled back with its record.
    Older,
}

pub fn arrival(held: Option<u64>, version: u64) -> Arrival {
    match held {
        Some(current) if version < current => Arrival::Older,
        Some(current) if version == current => Arrival::Same,
        _ => Arrival::Newer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_signing::{sign_in, testing};
    use proptest::prelude::*;
    use serde_json::json;

    fn payload(version: u64) -> Value {
        json!({ "schema": 1, "target": "t", "version": version, "workloads": [] })
    }

    fn signer(ca: &testing::Authority, identity: &'static str) -> testing::Signer {
        testing::signer(
            ca,
            testing::Spec {
                identity,
                ..testing::Spec::default()
            },
        )
    }

    fn signed(signer: &testing::Signer, domain: Domain, payload: Value) -> Vec<u8> {
        let document = sign_in(
            domain,
            payload,
            std::slice::from_ref(&signer.cert_pem),
            &signer.key_pem,
        )
        .unwrap();
        serde_json::to_vec(&document.to_value()).unwrap()
    }

    fn trust(ca: &testing::Authority) -> Trust {
        Trust::from_pem(std::slice::from_ref(&ca.pem)).unwrap()
    }

    #[test]
    fn a_record_the_pipeline_signed_is_believed() {
        let ca = testing::root("deployment");
        let text = signed(&signer(&ca, SIGNER), Domain::DEPLOYMENT_RECORD, payload(3));
        assert_eq!(
            read_record(&text, &trust(&ca), testing::now())
                .unwrap()
                .version,
            3
        );
    }

    #[test]
    fn flux_is_under_the_same_ca_and_is_not_believed() {
        let ca = testing::root("deployment");
        let text = signed(&signer(&ca, "flux"), Domain::DEPLOYMENT_RECORD, payload(3));
        let why = read_record(&text, &trust(&ca), testing::now()).unwrap_err();
        assert!(why.contains("flux"), "{why}");
    }

    #[test]
    fn a_signature_made_for_something_else_is_not_believed() {
        let ca = testing::root("deployment");
        let text = signed(&signer(&ca, SIGNER), Domain::CONFIGURATION, payload(3));
        assert!(read_record(&text, &trust(&ca), testing::now()).is_err());
    }

    #[test]
    fn polars_own_ca_is_not_the_one_trusted() {
        let (deployment, polar) = (testing::root("deployment"), testing::root("polar"));
        let text = signed(
            &signer(&polar, SIGNER),
            Domain::DEPLOYMENT_RECORD,
            payload(3),
        );
        assert!(read_record(&text, &trust(&deployment), testing::now()).is_err());
    }

    #[test]
    fn a_record_changed_after_it_was_signed_is_not_believed() {
        let ca = testing::root("deployment");
        let text = signed(&signer(&ca, SIGNER), Domain::DEPLOYMENT_RECORD, payload(3));
        let changed = String::from_utf8(text)
            .unwrap()
            .replace("\"version\":3", "\"version\":4");
        assert!(read_record(changed.as_bytes(), &trust(&ca), testing::now()).is_err());
    }

    #[test]
    fn what_is_not_a_document_is_refused() {
        let ca = testing::root("deployment");
        assert!(read_record(b"not json", &trust(&ca), testing::now()).is_err());
        assert!(read_record(b"{}", &trust(&ca), testing::now()).is_err());
    }

    proptest! {
        /// The held version never goes back, over any order of arrivals.
        #[test]
        fn the_version_held_only_ever_rises(versions in prop::collection::vec(0u64..50, 0..40)) {
            let mut held = None;
            for version in versions {
                let before = held;
                match arrival(held, version) {
                    Arrival::Newer => {
                        prop_assert!(before.is_none_or(|v| version > v));
                        held = Some(version);
                    }
                    Arrival::Same => prop_assert_eq!(before, Some(version)),
                    Arrival::Older => prop_assert!(before.is_some_and(|v| version < v)),
                }
            }
        }
    }
}
