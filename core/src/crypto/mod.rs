use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CoreError, Result};

/// Ed25519 key pair for signing and verification
#[derive(Clone)]
pub struct KeyPair {
    /// Public key
    pub public: PublicKey,
    /// Secret key (private key)
    pub secret: SecretKey,
}

/// Ed25519 public key
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

/// Ed25519 secret key (private key)
#[derive(Clone)]
pub struct SecretKey(SigningKey);

// Custom Serialize implementation for PublicKey
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

// Custom Deserialize implementation for PublicKey
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl KeyPair {
    /// Generate a new random key pair
    ///
    /// # Example
    ///
    /// ```
    /// use core::crypto::KeyPair;
    ///
    /// let keypair = KeyPair::generate();
    /// ```
    pub fn generate() -> Self {
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();

        Self {
            public: PublicKey(verifying_key),
            secret: SecretKey(signing_key),
        }
    }

    /// Create a key pair from raw bytes
    ///
    /// # Arguments
    ///
    /// * `secret_bytes` - 32-byte secret key
    ///
    /// # Errors
    ///
    /// Returns error if the secret key bytes are invalid
    pub fn from_secret_bytes(secret_bytes: &[u8]) -> Result<Self> {
        if secret_bytes.len() != 32 {
            return Err(CoreError::InvalidSecretKey(
                "Secret key must be 32 bytes".to_string(),
            ));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret_bytes);

        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            public: PublicKey(verifying_key),
            secret: SecretKey(signing_key),
        })
    }

    /// Get the secret key as bytes
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.0.to_bytes()
    }

    /// Sign a message with this key pair
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A 64-byte signature
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: Signature = self.secret.0.sign(message);
        signature.to_bytes()
    }

    /// Encode the secret key as base58
    pub fn secret_to_base58(&self) -> String {
        bs58::encode(self.secret_bytes()).into_string()
    }

    /// Create a key pair from a base58-encoded secret key
    pub fn from_base58_secret(encoded: &str) -> Result<Self> {
        let bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| CoreError::DecodingError(format!("Base58 decode failed: {}", e)))?;

        Self::from_secret_bytes(&bytes)
    }
}

impl PublicKey {
    /// Create a public key from raw bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte public key
    ///
    /// # Errors
    ///
    /// Returns error if the public key bytes are invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CoreError::InvalidPublicKey(
                "Public key must be 32 bytes".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CoreError::InvalidPublicKey(format!("Invalid key bytes: {}", e)))?;

        Ok(Self(verifying_key))
    }

    /// Get the public key as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Encode the public key as base58
    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    /// Create a public key from a base58-encoded string
    pub fn from_base58(encoded: &str) -> Result<Self> {
        let bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| CoreError::DecodingError(format!("Base58 decode failed: {}", e)))?;

        Self::from_bytes(&bytes)
    }

    /// Encode the public key as hexadecimal
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Create a public key from a hexadecimal string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CoreError::DecodingError(format!("Hex decode failed: {}", e)))?;

        Self::from_bytes(&bytes)
    }

    /// Verify a signature on a message
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The 64-byte signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, error otherwise
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(CoreError::SignatureVerificationFailed);
        }

        let sig = Signature::from_bytes(signature.try_into().unwrap());

        self.0
            .verify(message, &sig)
            .map_err(|_| CoreError::SignatureVerificationFailed)
    }
}

impl SecretKey {
    /// Get the secret key as bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

// Implement Debug for SecretKey without exposing the key material
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        assert_eq!(keypair.public.to_bytes().len(), 32);
        assert_eq!(keypair.secret_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let message = b"Hello, World!";

        let signature = keypair.sign(message);
        assert_eq!(signature.len(), 64);

        // Verification should succeed
        assert!(keypair.public.verify(message, &signature).is_ok());

        // Verification with wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(keypair.public.verify(wrong_message, &signature).is_err());

        // Verification with wrong signature should fail
        let wrong_signature = [0u8; 64];
        assert!(keypair.public.verify(message, &wrong_signature).is_err());
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = KeyPair::generate();
        let secret_bytes = keypair.secret_bytes();

        // Reconstruct from bytes
        let restored_keypair = KeyPair::from_secret_bytes(&secret_bytes).unwrap();

        assert_eq!(
            keypair.public.to_bytes(),
            restored_keypair.public.to_bytes()
        );
        assert_eq!(keypair.secret_bytes(), restored_keypair.secret_bytes());
    }

    #[test]
    fn test_base58_encoding() {
        let keypair = KeyPair::generate();

        // Test public key
        let public_base58 = keypair.public.to_base58();
        let restored_public = PublicKey::from_base58(&public_base58).unwrap();
        assert_eq!(keypair.public.to_bytes(), restored_public.to_bytes());

        // Test secret key
        let secret_base58 = keypair.secret_to_base58();
        let restored_keypair = KeyPair::from_base58_secret(&secret_base58).unwrap();
        assert_eq!(
            keypair.public.to_bytes(),
            restored_keypair.public.to_bytes()
        );
    }

    #[test]
    fn test_hex_encoding() {
        let keypair = KeyPair::generate();

        let hex = keypair.public.to_hex();
        let restored = PublicKey::from_hex(&hex).unwrap();

        assert_eq!(keypair.public.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Test invalid public key length
        let invalid_public = PublicKey::from_bytes(&[0u8; 16]);
        assert!(invalid_public.is_err());

        // Test invalid secret key length
        let invalid_secret = KeyPair::from_secret_bytes(&[0u8; 16]);
        assert!(invalid_secret.is_err());
    }

    #[test]
    fn test_signature_verification_with_different_keypair() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let message = b"Test message";

        let signature = keypair1.sign(message);

        // Verify with correct public key
        assert!(keypair1.public.verify(message, &signature).is_ok());

        // Verify with different public key should fail
        assert!(keypair2.public.verify(message, &signature).is_err());
    }
}
