//! DID (Decentralized Identifier) module
//!
//! Implements the `did:key` method for Ed25519 keys.
//!
//! A `did:key` DID is derived directly from a public key:
//! ```text
//! did:key:z6Mk...
//!         │└─────── base58btc(multicodec_prefix || public_key_bytes)
//!         └──────── multibase prefix 'z' (base58btc)
//! ```
//!
//! For Ed25519, the multicodec prefix is `0xed 0x01` (unsigned varint of 0xed).

pub mod document;
pub mod resolver;

pub use document::{DidDocument, VerificationMethod};
pub use resolver::{DidResolver, KeyMethodResolver};

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;
use crate::error::{CoreError, Result};

/// Multicodec prefix for Ed25519 public keys (unsigned varint of 0xed).
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// Multibase prefix character for base58btc encoding.
const MULTIBASE_BASE58BTC: char = 'z';

/// A Decentralized Identifier using the `did:key` method.
///
/// # Example
///
/// ```
/// use core::crypto::KeyPair;
/// use core::did::Did;
///
/// let keypair = KeyPair::generate();
/// let did = Did::from_public_key(&keypair.public);
/// assert!(did.to_string().starts_with("did:key:z"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Did {
    /// DID method name (e.g. "key").
    method: String,
    /// Method-specific identifier (e.g. "z6Mk...").
    identifier: String,
}

impl Did {
    /// Create a `did:key` DID from an Ed25519 public key.
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        // multicodec prefix || raw public key bytes
        let mut bytes = Vec::with_capacity(2 + 32);
        bytes.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
        bytes.extend_from_slice(&public_key.to_bytes());

        // multibase: 'z' prefix + base58btc encoding
        let encoded = bs58::encode(&bytes).into_string();
        let identifier = format!("{}{}", MULTIBASE_BASE58BTC, encoded);

        Self {
            method: "key".to_string(),
            identifier,
        }
    }

    /// Parse a DID string into a `Did`.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID is malformed or uses an unsupported method.
    pub fn parse(did_str: &str) -> Result<Self> {
        let parts: Vec<&str> = did_str.splitn(3, ':').collect();

        if parts.len() != 3 {
            return Err(CoreError::InvalidDidFormat(format!(
                "Expected format 'did:method:identifier', got '{}'",
                did_str
            )));
        }

        if parts[0] != "did" {
            return Err(CoreError::InvalidDidFormat(format!(
                "DID must start with 'did:', got '{}'",
                parts[0]
            )));
        }

        let method = parts[1].to_string();
        let identifier = parts[2].to_string();

        if method != "key" {
            return Err(CoreError::UnsupportedMethod(method));
        }

        if identifier.is_empty() {
            return Err(CoreError::InvalidDidFormat(
                "Identifier cannot be empty".to_string(),
            ));
        }

        Ok(Self { method, identifier })
    }

    /// Extract the Ed25519 public key encoded in this `did:key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is not a valid base58btc-encoded
    /// Ed25519 multicodec key.
    pub fn to_public_key(&self) -> Result<PublicKey> {
        let mut chars = self.identifier.chars();
        let prefix = chars
            .next()
            .ok_or_else(|| CoreError::InvalidDidFormat("Empty identifier".to_string()))?;

        if prefix != MULTIBASE_BASE58BTC {
            return Err(CoreError::InvalidDidFormat(format!(
                "Unsupported multibase prefix '{}', expected '{}'",
                prefix, MULTIBASE_BASE58BTC
            )));
        }

        let encoded: String = chars.collect();
        let bytes = bs58::decode(&encoded)
            .into_vec()
            .map_err(|e| CoreError::DecodingError(format!("Base58 decode failed: {}", e)))?;

        if bytes.len() != 34 {
            return Err(CoreError::InvalidPublicKey(format!(
                "Expected 34 bytes (2 prefix + 32 key), got {}",
                bytes.len()
            )));
        }

        if bytes[0..2] != ED25519_MULTICODEC_PREFIX {
            return Err(CoreError::InvalidPublicKey(
                "Not an Ed25519 multicodec key".to_string(),
            ));
        }

        PublicKey::from_bytes(&bytes[2..])
    }

    /// Get the DID method name.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Get the method-specific identifier.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.identifier)
    }
}

// Serialize a Did as its string form ("did:key:z...").
impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// Deserialize a Did from its string form.
impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Did::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_did_generation() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        assert_eq!(did.method(), "key");
        assert!(did.to_string().starts_with("did:key:z"));
    }

    #[test]
    fn test_did_parse() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let did_str = did.to_string();

        let parsed = Did::parse(&did_str).unwrap();
        assert_eq!(parsed, did);
    }

    #[test]
    fn test_did_roundtrip_public_key() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        let recovered = did.to_public_key().unwrap();
        assert_eq!(recovered.to_bytes(), keypair.public.to_bytes());
    }

    #[test]
    fn test_parse_invalid_format() {
        assert!(Did::parse("not-a-did").is_err());
        assert!(Did::parse("did:key").is_err());
        assert!(Did::parse("foo:key:z123").is_err());
    }

    #[test]
    fn test_parse_unsupported_method() {
        let result = Did::parse("did:web:example.com");
        assert!(matches!(result, Err(CoreError::UnsupportedMethod(_))));
    }

    #[test]
    fn test_serde_roundtrip() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        let json = serde_json::to_string(&did).unwrap();
        let deserialized: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did, deserialized);
    }
}
