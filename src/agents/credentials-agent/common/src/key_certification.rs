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

//! A workload's crypto actor asking the credentials agent to certify a key the workload keeps for one purpose
//! (docs/plans/record-store/to-main.md): today a log's checkpoint key. The key is the workload's, stable across its
//! pods and kept on its own volume; the crypto actor makes it and asks, and the domain never touches it. The credentials
//! agent certifies it only for a workload whose build gives it that purpose (the `checkpoints` group, which the
//! authority model carries from its scaffold), judged by the broker-stamped identity of whoever asks, through
//! cert-issuer's certificate for that purpose alone.

use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// The group a workload is in when its build keeps a checkpoint key (polar-topics' `Rule::Checkpoints`): what the
/// credentials agent reads in the authority model before it certifies one.
pub const CHECKPOINTS_GROUP: &str = "checkpoints";

/// What a key is for: the certificate says it, and the key does nothing else.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Deserialize,
    Serialize,
    Archive,
    SerdeDeserialize,
    SerdeSerialize,
)]
pub enum KeyPurpose {
    /// Signing a log's checkpoints (cert-issuer's `CertType::Checkpoint`).
    Checkpoint,
}

/// Certify the key that signed `csr_pem`, for `purpose`, for the workload that asks. Published on
/// `credentials-key-certification-requests`, in an `Envelope`; answered with a [`KeyCertificationReply`].
#[derive(
    Debug, Clone, PartialEq, Deserialize, Serialize, Archive, SerdeDeserialize, SerdeSerialize,
)]
pub struct KeyCertificationRequest {
    pub csr_pem: String,
    pub purpose: KeyPurpose,
}

/// Why a key was not certified.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Deserialize,
    Serialize,
    Archive,
    SerdeDeserialize,
    SerdeSerialize,
)]
pub enum KeyCertificationRefusal {
    /// The asker is no workload whose build keeps such a key, or it named none.
    NotPermitted,
    /// cert-issuer did not sign it.
    SigningFailed,
}

/// The answer, on `credentials-key-certification-replies`, under the request's correlation id. One reply topic for
/// every asker: a certificate is public, and each crypto actor takes its own by the id.
#[derive(
    Debug, Clone, PartialEq, Deserialize, Serialize, Archive, SerdeDeserialize, SerdeSerialize,
)]
pub enum KeyCertificationReply {
    Certified {
        certificate_pem: String,
        ca_chain_pem: String,
        /// When it expires, in Unix seconds: the crypto actor asks again at half its life.
        expires_at: i64,
    },
    Refused {
        reason: KeyCertificationRefusal,
    },
}
