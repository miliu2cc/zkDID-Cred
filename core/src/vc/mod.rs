//! Verifiable Credential (VC) module.
//!
//! Implements a W3C Verifiable Credentials Data Model subset:
//! - Credential data structures ([`VerifiableCredential`], [`CredentialSubject`])
//! - Issuance: an issuer signs a credential with its DID key ([`issuer`])
//! - Verification: a verifier checks the signature via the issuer DID ([`verifier`])
//!
//! Credentials are immutable once issued. To change a credential, revoke the
//! old one and issue a new one (see [`CredentialStatus`]).

pub mod issuer;
pub mod verifier;

pub use issuer::issue_credential;
pub use verifier::verify_credential;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The base VC context URI.
pub const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";

/// A W3C Verifiable Credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// Unique credential identifier (e.g. a UUID URN or issuer URL).
    pub id: String,

    /// Credential types, e.g. ["VerifiableCredential", "UniversityDegreeCredential"].
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// DID of the issuing authority (the university).
    pub issuer: String,

    /// Issuance timestamp (RFC3339).
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    /// Optional expiration timestamp (RFC3339).
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,

    /// The claims about the subject (the student).
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,

    /// Optional revocation/status information.
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    /// Cryptographic proof. `None` before signing; populated after issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// The subject of a credential and the claims made about them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// DID of the subject (the student).
    pub id: String,

    /// Arbitrary claims (e.g. gpa, degree, courses). Kept as a JSON object so
    /// different credential types can carry different fields.
    #[serde(flatten)]
    pub claims: Value,
}

/// Revocation / status information for a credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// Status entry id (e.g. a revocation list entry URL).
    pub id: String,
    /// Status type, e.g. "RevocationList2020Status".
    #[serde(rename = "type")]
    pub type_: String,
}

/// A linked-data proof attached to a credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    /// Proof type, e.g. "Ed25519Signature2020".
    #[serde(rename = "type")]
    pub type_: String,
    /// When the proof was created (RFC3339).
    pub created: String,
    /// The verification method (DID URL) whose key produced the signature.
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    /// The intended use of the proof, e.g. "assertionMethod".
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    /// The detached signature, base58btc-encoded.
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// The proof type string used by this implementation.
pub const PROOF_TYPE_ED25519: &str = "Ed25519Signature2020";
/// The default proof purpose for credential issuance.
pub const PROOF_PURPOSE_ASSERTION: &str = "assertionMethod";

impl VerifiableCredential {
    /// Return a copy of this credential with `proof` cleared.
    ///
    /// This is the canonical form that gets signed and verified: the signature
    /// covers every field except the proof itself.
    pub(crate) fn without_proof(&self) -> Self {
        let mut clone = self.clone();
        clone.proof = None;
        clone
    }
}
