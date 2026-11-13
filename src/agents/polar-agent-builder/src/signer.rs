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

//! The signer: what an agent with the `signing` capability has its evidence records signed with
//! (docs/architecture/key-custody.md, "Workload signing keys", item 4).
//!
//! The key is the pod's own, in the custody daemon's signer slot: made there, never leaving it, never escrowed. The
//! crypto actor signs with it (`polar_crypto::records`), as it does every other key use of the agent's: it is spawned
//! unnamed, so nothing finds it by name; it takes no topic of this, so nothing outside the process reaches it; and it
//! outlives the domain, so the infrastructure can still sign a record saying it ended one. The domain has a
//! [`SignerHandle`], which signs an [`EvidenceRecord`] and nothing else:
//! never bytes, never a document of another kind. The signer makes the record's signing input, in the evidence domain,
//! and signs only a record of a type the slot's certificate names (`c:record-evidence:<type>`); the daemon holds the key
//! and signs what it is given. A reader holds every record to its signer's certificate as well, so a record signed
//! outside its types is refused where it is read.
//!
//! A review rule the type cannot hold: what the domain asks to sign is built from its own observations, never from
//! content it received. A record in the agent's name says the agent saw it; signing another's words would make the
//! agent a confused deputy.
//!
//! ```
//! # use polar_agent_builder::signer::{EvidenceRecord, RecordSigner, SignerHandle};
//! async fn what_the_domain_has(signer: &SignerHandle) {
//!     let record = EvidenceRecord::new("attestation", serde_json::Map::new()).unwrap();
//!     let _ = signer.sign(record).await;
//! }
//! ```
//!
//! No actor to send messages to, and nothing that signs bytes. These do not compile:
//!
//! ```compile_fail
//! # use polar_agent_builder::signer::SignerHandle;
//! fn the_actor(signer: &SignerHandle) {
//!     let _ = signer.actor();
//! }
//! ```
//!
//! ```compile_fail
//! # use polar_agent_builder::signer::{RecordSigner, SignerHandle};
//! async fn bytes(signer: &SignerHandle) {
//!     let _ = signer.sign(b"anything".to_vec()).await;
//! }
//! ```

use async_trait::async_trait;
use polar_crypto::CryptoMessage;
use ractor::ActorRef;

pub use polar_crypto::records::{EvidenceRecord, NotARecord, SignError};

/// What the signer needs of the environment: the custody daemon's socket, which the Cassini client's section declares
/// (`POLAR_CUSTODY_SOCKET`), since the signing key is the daemon's and there is no key file for it.
pub static SECTION: polar_env::Section = polar_env::Section {
    name: "signer",
    vars: &[],
    relations: |env| match polar_custody::environment::CUSTODY_SOCKET.read(env) {
        Ok(Some(_)) => Vec::new(),
        Ok(None) => vec![format!(
            "{} is required to sign records: the signing key is the custody daemon's",
            polar_custody::environment::CUSTODY_SOCKET.name()
        )],
        Err(e) => vec![e.to_string()],
    },
};

/// What the domain signs with. A trait, so that a domain's tests can sign with a fake.
#[async_trait]
pub trait RecordSigner: Send + Sync {
    /// `record`, signed with the pod's signing key, as the evidence document that goes in the evidence repository.
    async fn sign(&self, record: EvidenceRecord) -> Result<polar_signing::Document, SignError>;
}

/// The domain's way to the crypto actor's record signing.
#[derive(Clone)]
pub struct SignerHandle {
    actor: ActorRef<CryptoMessage>,
}

impl SignerHandle {
    pub(crate) fn new(actor: ActorRef<CryptoMessage>) -> Self {
        Self { actor }
    }

    /// The crypto actor it reaches, for the builder's tests.
    #[cfg(test)]
    pub(crate) fn actor(&self) -> &ActorRef<CryptoMessage> {
        &self.actor
    }
}

#[async_trait]
impl RecordSigner for SignerHandle {
    async fn sign(&self, record: EvidenceRecord) -> Result<polar_signing::Document, SignError> {
        ractor::call!(self.actor, |reply| CryptoMessage::SignRecord {
            record,
            reply
        })
        .map_err(|e| SignError::Unavailable(e.to_string()))?
    }
}
