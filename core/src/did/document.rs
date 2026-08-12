//! DID Document generation and (de)serialization.
//!
//! Implements a W3C-compliant DID Document for the `did:key` method.

use serde::{Deserialize, Serialize};

use super::Did;
use crate::error::{CoreError, Result};

/// The DID Core context URI.
const DID_CONTEXT_V1: &str = "https://www.w3.org/ns/did/v1";
/// The Ed25519 2020 signature suite context URI.
const ED25519_CONTEXT_2020: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
/// The verification method type for Ed25519 keys.
const ED25519_VERIFICATION_KEY_2020: &str = "Ed25519VerificationKey2020";

/// A single verification method within a DID Document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Fully-qualified id, e.g. "did:key:z6Mk...#z6Mk...".
    pub id: String,
    /// Key type, e.g. "Ed25519VerificationKey2020".
    #[serde(rename = "type")]
    pub type_: String,
    /// The DID that controls this key.
    pub controller: String,
    /// The public key in multibase form (matches the did:key identifier).
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// A W3C DID Document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID this document describes.
    pub id: String,
    /// Public keys associated with the DID.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Verification method references usable for authentication.
    pub authentication: Vec<String>,
    /// Verification method references usable for asserting claims (VC signing).
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
}

impl DidDocument {
    /// Build a DID Document from a `did:key` DID.
    ///
    /// For `did:key`, the verification method fragment reuses the identifier,
    /// so the full method id is `did:key:z...#z...`.
    pub fn from_did(did: &Did) -> Self {
        let did_str = did.to_string();
        let identifier = did.identifier();
        let method_id = format!("{}#{}", did_str, identifier);

        let verification_method = VerificationMethod {
            id: method_id.clone(),
            type_: ED25519_VERIFICATION_KEY_2020.to_string(),
            controller: did_str.clone(),
            public_key_multibase: identifier.to_string(),
        };

        Self {
            context: vec![DID_CONTEXT_V1.to_string(), ED25519_CONTEXT_2020.to_string()],
            id: did_str,
            verification_method: vec![verification_method],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id],
        }
    }

    /// Serialize the document to pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| CoreError::SerializationError(e.to_string()))
    }

    /// Deserialize a document from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| CoreError::DeserializationError(e.to_string()))
    }

    /// Look up a verification method by its full id.
    pub fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method.iter().find(|vm| vm.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_document_from_did() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let doc = DidDocument::from_did(&did);

        assert_eq!(doc.id, did.to_string());
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].type_,
            ED25519_VERIFICATION_KEY_2020
        );
    }

    #[test]
    fn test_document_json_roundtrip() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let doc = DidDocument::from_did(&did);

        let json = doc.to_json().unwrap();
        let restored = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc, restored);
    }

    #[test]
    fn test_get_verification_method() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let doc = DidDocument::from_did(&did);

        let method_id = &doc.verification_method[0].id;
        assert!(doc.get_verification_method(method_id).is_some());
        assert!(
            doc.get_verification_method("did:key:zNonExistent")
                .is_none()
        );
    }
}
