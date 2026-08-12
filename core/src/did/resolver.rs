//! DID resolution.
//!
//! For `did:key`, resolution is purely local: the DID Document is
//! reconstructed from the public key encoded in the DID itself, with no
//! network or ledger lookup required.

use super::{Did, DidDocument};
use crate::error::Result;

/// A resolver turns a DID string into a DID Document.
pub trait DidResolver {
    /// Resolve a DID string into its DID Document.
    fn resolve(&self, did_str: &str) -> Result<DidDocument>;
}

/// Resolver for the `did:key` method.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyMethodResolver;

impl KeyMethodResolver {
    /// Create a new `did:key` resolver.
    pub fn new() -> Self {
        Self
    }
}

impl DidResolver for KeyMethodResolver {
    fn resolve(&self, did_str: &str) -> Result<DidDocument> {
        // Parsing validates the method and that the identifier decodes to a
        // valid Ed25519 key.
        let did = Did::parse(did_str)?;
        did.to_public_key()?;
        Ok(DidDocument::from_did(&did))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_resolve_valid_did() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let did_str = did.to_string();

        let resolver = KeyMethodResolver::new();
        let doc = resolver.resolve(&did_str).unwrap();

        assert_eq!(doc.id, did_str);
    }

    #[test]
    fn test_resolve_invalid_did() {
        let resolver = KeyMethodResolver::new();
        assert!(resolver.resolve("did:web:example.com").is_err());
        assert!(resolver.resolve("not-a-did").is_err());
    }

    #[test]
    fn test_resolve_matches_public_key() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        let resolver = KeyMethodResolver::new();
        let doc = resolver.resolve(&did.to_string()).unwrap();

        // The verification method's multibase key should match the DID identifier.
        assert_eq!(
            doc.verification_method[0].public_key_multibase,
            did.identifier()
        );
    }
}
