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

//! Shared types between the cert issuer and its init container client.
//!
//! Kept separate so the wire protocol is defined in exactly one place
//! and both ends are forced to agree on it.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
pub mod ca_root;
pub mod capability;
pub mod csr_san;
pub mod custody;
pub mod evidence;
pub mod group;
pub mod held;
pub mod hierarchy;
pub mod identity;
pub mod instance;
pub mod key_match;
pub mod keypair;
pub mod permission;
pub mod public_key;
pub mod record;
pub mod serial;
pub mod ticket;

// cert_issuer_common/src/lib.rs — add to IssueRequest
#[derive(
    minicbor::Encode,
    minicbor::Decode,
    Debug,
    Clone,
    Default,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    clap::ValueEnum,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cbor(index_only)]
pub enum CertType {
    #[default]
    #[n(0)]
    Client,
    #[n(1)]
    Server,
    /// A service's own durable, agent-to-agent encryption identity --
    /// not a client/server TLS role at all, and deliberately never
    /// treated as one. See credentials-agent-architecture.md's own
    /// "Agent escrow identity" section (which calls this a service's
    /// "escrow keypair" -- named Service here specifically to avoid
    /// conflating the certificate's own type with the separate
    /// mechanism, described in the same document, that later escrows
    /// it alongside its private key). It is the application layer's certificate (whom a secret is encrypted to) and
    /// the mTLS certificate the transport layer's (who may hold a connection), so it carries the one extended key
    /// usage `emailProtection`, which no TLS stack takes for a client or a server.
    #[n(2)]
    Service,
    /// A key the holder signs its own statements with, never a TLS role: `digitalSignature` and the one extended key
    /// usage `id-kp-documentSigning` ([`OID_DOCUMENT_SIGNING`]), which no TLS stack takes for a client or a server.
    /// Signed only on `/internal/issue`, for the internal caller's own identity: the credentials agent's session
    /// offers are signed with one (docs/architecture/core-restarts.md, "1c in detail").
    #[n(3)]
    Signing,
    /// The custody daemon's own certificate (docs/architecture/key-custody.md, "Part A's bootstrap: the custodian"):
    /// client authentication, for its own Cassini session, named `custody.<X>` for the workload X its pod's token
    /// proves ([`custody::custodian_identity`]). Its `p:custody:` names say what it may ask the credentials agent for
    /// on X's behalf. Signed only on a token, never on `/internal/issue`: it is what the pod proves itself for.
    #[n(4)]
    Custody,
    /// A key that signs a log's checkpoints and nothing else (docs/architecture/record-store.md, "L2, checkpoints"):
    /// `digitalSignature` and the one extended key usage `id-polar-kp-logCheckpoint` ([`OID_LOG_CHECKPOINT`]), so no
    /// TLS stack takes it and no check of a signed document does. Signed only on `/internal/issue`, for the internal
    /// caller's own identity and no other name: the credentials agent's ledger key has one.
    #[n(5)]
    Checkpoint,
}

/// `id-kp-documentSigning` (RFC 9336): the extended key usage of a [`CertType::Signing`] certificate.
pub const OID_DOCUMENT_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 36];

/// Polar's own arc, an X.667 UUID OID (`a18fa2ab-c873-451d-bff8-a0d22b3b6662`), which needs no registration. Polar
/// allocates under it.
const POLAR_ARC: u128 = 214_751_505_132_549_872_223_803_780_954_079_323_746;

/// `id-polar-kp-logCheckpoint`, `2.25.<POLAR_ARC>.1`: the extended key usage of a [`CertType::Checkpoint`]
/// certificate, as dotted text. Its arc does not fit the `u64` arcs the other OIDs are written in, so its encoding is
/// [`log_checkpoint_oid`]'s.
pub const OID_LOG_CHECKPOINT: &str = "2.25.214751505132549872223803780954079323746.1";

/// The content octets of `id-polar-kp-logCheckpoint`'s DER encoding (X.690, 8.19): what a parsed OID's bytes are.
pub fn log_checkpoint_oid() -> Vec<u8> {
    // The first two arcs share one subidentifier, 2 × 40 + 25.
    let mut content = vec![105];
    let mut digits = Vec::new();
    let mut arc = POLAR_ARC;
    while arc > 0 {
        digits.push((arc & 0x7f) as u8);
        arc >>= 7;
    }
    content.extend(
        digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, d)| if i + 1 < digits.len() { d | 0x80 } else { *d }),
    );
    content.push(1);
    content
}

/// The DER value of an extended key usage extension holding `id-polar-kp-logCheckpoint` alone: a SEQUENCE of one OID.
pub fn log_checkpoint_extended_key_usage() -> Vec<u8> {
    let oid = log_checkpoint_oid();
    let mut der = vec![0x30, (oid.len() + 2) as u8, 0x06, oid.len() as u8];
    der.extend(oid);
    der
}

impl std::fmt::Display for CertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Service => "service",
            Self::Signing => "signing",
            Self::Custody => "custody",
            Self::Checkpoint => "checkpoint",
        };
        write!(f, "{s}")
    }
}

/// Admin-provisioned fallback values for Subject DN fields the
/// user's own CSR didn't set -- see the Polar user-account CSR flow
/// (credentials-agent-architecture.md's "User self-service issuance"
/// section and its account-provisioning extension). Plain,
/// unvalidated strings on the wire, matching IssueRequest's own
/// convention for extra_sans (also a plain `Vec<String>`); real
/// validation happens exactly once, in cert-issuer/server's csr
/// module, via the same PersonalName/JobTitle/PhoneNumber
/// constructors the CSR's own fields go through -- not duplicated
/// here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectDnDefaults {
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub title: Option<String>,
    pub telephone_number: Option<String>,
}

/// Request body for `POST /issue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRequest {
    /// PEM-encoded CSR. The SAN must match the workload identity claim
    /// from the bearer token, or the cert issuer rejects with `IDENTITY_MISMATCH`.
    pub csr_pem: String,
    pub cert_type: CertType,
    #[serde(default)]
    pub extra_sans: Vec<String>,
    /// Admin-provisioned defaults for Subject DN fields (given name,
    /// surname, title, telephone number), used only for whichever
    /// fields the CSR itself doesn't set -- the CSR's own value
    /// always wins when present. `None` for every issuance path that
    /// has no such defaults (ordinary workload issuance, admin
    /// bootstrap).
    #[serde(default)]
    pub subject_dn_defaults: Option<SubjectDnDefaults>,
}

/// Successful response body for `POST /issue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueResponse {
    /// PEM-encoded certificate chain (leaf first, then intermediates).
    pub certificate_pem: String,
    /// PEM-encoded CA certificate(s) for the trust chain.
    pub ca_chain_pem: String,
    /// The issued certificate's own X.509 serial number -- the join
    /// key for revocation (credentials-agent's Revoke events, and any
    /// future CRL, are keyed on this, not session_id below, which is
    /// a separate, per-request audit-correlation value).
    pub serial_number: String,
    /// UUID for audit correlation. The init container surfaces this
    /// in its log output so operators can grep across logs and graph events.
    pub session_id: String,
    /// Certificate `notAfter` in RFC3339. The init container uses this
    /// to compute renewal-restart timing if it ever needs to.
    pub expires_at: OffsetDateTime,
}

/// Successful response body for `POST /validate`. Distinct from
/// `IssueResponse` -- exists specifically for credentials-agent's
/// two-call issuance flow (validate first to get the real identity
/// for a grant lookup, then issue separately once permitted SANs are
/// known).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateResponse {
    /// The raw claim value -- not the normalized, DNS-safe identity
    /// /issue's CSR-matching logic uses. Grants are keyed on this
    /// exact raw value, per credentials-agent-architecture.md.
    pub workload_identity: String,
    pub instance_binding: Option<String>,
    /// The standard JWT `jti` claim, if present. See
    /// oidc::ValidatedClaims::jti's own doc comment on cert-issuer's
    /// side for what this is -- generic claim extraction, no policy
    /// attached here either; credentials-agent decides what (if
    /// anything) to do with it.
    pub jti: Option<String>,
    /// The pod's name, from the issuer's `instance_name_claim` (`kubernetes.io/pod/name` for a Kubernetes token), when
    /// it has one: what a multi-instance workload's certificate names its instance by, for people, beside the pod UID in
    /// `instance_binding` (docs/architecture/authority-model.md, "Multi-instance workloads"). Absent from a reply of a
    /// cert-issuer before it existed.
    #[serde(default)]
    pub instance_name: Option<String>,
    /// The normalized, DNS-safe identity /issue's CSR-matching logic
    /// will actually check against -- computed via the same
    /// normalize_identity call /issue itself uses, so a client
    /// building a CSR from this value is guaranteed to match, never a
    /// second, independent computation that could drift. Only
    /// populated when the request explicitly asks for it via
    /// ValidateRequest::include_normalized_identity -- never returned
    /// unrequested, since most callers of this endpoint (the
    /// issuance flow's own internal /validate call) have no use for
    /// it at all.
    pub normalized_identity: Option<String>,
}

/// Request body for `POST /validate`. Previously took no body at all
/// (just the bearer token via the Authorization header) -- this is
/// the first real parameter it's ever had.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidateRequest {
    #[serde(default)]
    pub include_normalized_identity: bool,
}

/// The account an internally-issued certificate belongs to, written into
/// its Subject DN as the standard `uid` and `mail` attributes. Unlike
/// `SubjectDnDefaults`, these are authoritative: they come only from the
/// caller (credentials-agent, which matched them against the ledger), never
/// from the CSR, and a CSR that claims its own `uid` or `mail` is ignored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSubject {
    pub username: String,
    pub email: String,
}

/// Request body for the internal, mTLS-gated /internal/issue
/// endpoint. Reachable only over cert-issuer's mTLS listener, from a
/// caller whose own peer certificate matches the configured
/// internal-caller allowlist -- there is no bearer token here at all,
/// unlike IssueRequest. The caller (credentials-agent) has already
/// done its own authorization work before ever making this call
/// (a K8s-token check for admin bootstrap, a username/email match
/// for an account claim); cert-issuer's only remaining job is
/// verifying the caller's own mTLS identity and then signing exactly
/// what it's asked to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalIssueRequest {
    pub csr_pem: String,
    /// The identity to sign for -- asserted directly by the caller,
    /// not derived from any token. Every caller of this endpoint
    /// (account claims, admin bootstrap) has no token asserting an
    /// identity at all; the caller's own prior authorization work is
    /// what makes asserting this directly safe.
    pub identity: String,
    pub cert_type: CertType,
    #[serde(default)]
    pub extra_sans: Vec<String>,
    #[serde(default)]
    pub subject_dn_defaults: Option<SubjectDnDefaults>,
    /// Authoritative username and email for an account certificate.
    /// `None` for every other internal issuance.
    #[serde(default)]
    pub account_subject: Option<AccountSubject>,
    /// The pod instance a workload's certificate is for, recorded as a token's would be: a custodian's, when the
    /// credentials agent asks on a custodian's behalf (docs/architecture/key-custody.md, "Part A's bootstrap: the
    /// custodian"). `None` for every other internal issuance.
    #[serde(default)]
    pub instance_binding: Option<String>,
    /// The latest the certificate may end (Unix seconds): its lifetime is cut to it, and nothing is signed once it is
    /// past. A custodian's end, so that none of its workload's certificates outlives it. `None`: the lifetime alone.
    #[serde(default)]
    pub expires_by: Option<i64>,
}

/// Error response body. Always returned on non-2xx responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssueError {
    pub outcome: IssueOutcome,
    /// Human-readable detail. Safe to log; should not contain secrets.
    pub detail: String,
}

/// The full set of issuance outcomes. Telemetry events use the same
/// enum so that grepping for an outcome in logs and metrics gives
/// matching results.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssueOutcome {
    Success,
    /// JWT signature verification failed, token expired, malformed, etc.
    InvalidToken,
    /// Token's `aud` claim does not match the configured audience.
    /// Surfaced as a distinct outcome because it's the most common
    /// deployment misconfiguration.
    InvalidAudience,
    /// The SAN in the submitted CSR does not match the workload identity
    /// claim extracted from the token.
    IdentityMismatch,
    /// CSR is malformed, uses a disallowed algorithm, or otherwise
    /// fails structural validation.
    InvalidCsr,
    /// Smallstep CA returned an error or was unreachable.
    CaUnavailable,
    /// Anything else. Indicates a bug or unexpected infrastructure failure.
    InternalError,
    /// /internal/issue only: the connection's own verified mTLS peer
    /// identity is not on the configured internal-caller allowlist --
    /// or no client certificate was presented at all. Distinct from
    /// InvalidToken, since no token is involved in this path.
    CallerNotAuthorized,
    /// The request is held (202): a bootstrap service the floor admits and the floor state does not, offered to the
    /// credentials agent to vouch for (docs/architecture/core-restarts.md, "3 in detail"). Send the same request again
    /// shortly; it is signed once vouched for, or refused.
    Held,
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("malformed request: {0}")]
    Malformed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dotted text of an OID's content octets, read as X.690 says, with arcs as wide as `u128`.
    fn dotted(content: &[u8]) -> String {
        let mut arcs: Vec<u128> = Vec::new();
        let mut arc: u128 = 0;
        for (i, b) in content.iter().enumerate() {
            assert!(
                !(b == &0x80 && (i == 0 || content[i - 1] & 0x80 == 0)),
                "a subidentifier in its fewest octets"
            );
            arc = (arc << 7) | u128::from(b & 0x7f);
            if b & 0x80 == 0 {
                arcs.push(arc);
                arc = 0;
            }
        }
        assert_eq!(arc, 0, "the last subidentifier ends");
        let first = arcs.remove(0);
        let (a, b) = if first < 80 {
            (first / 40, first % 40)
        } else {
            (2, first - 80)
        };
        std::iter::once(a)
            .chain(std::iter::once(b))
            .chain(arcs)
            .map(|arc| arc.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }

    #[test]
    fn the_checkpoint_usage_is_encoded_as_its_dotted_text_says() {
        assert_eq!(dotted(&log_checkpoint_oid()), OID_LOG_CHECKPOINT);
        assert_eq!(
            OID_LOG_CHECKPOINT,
            format!("2.25.{POLAR_ARC}.1"),
            "under Polar's arc"
        );
        let eku = log_checkpoint_extended_key_usage();
        assert_eq!(
            &eku[..4],
            &[0x30, eku.len() as u8 - 2, 0x06, eku.len() as u8 - 4]
        );
        assert_eq!(&eku[4..], log_checkpoint_oid().as_slice());
    }
}
