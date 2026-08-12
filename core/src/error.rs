use thiserror::Error;

/// Core library error types
#[derive(Error, Debug)]
pub enum CoreError {
    /// Invalid DID format
    #[error("Invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// Unsupported DID method
    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid secret key
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Encoding error
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Decoding error
    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// Cryptographic operation error
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

/// Result type alias for Core operations
pub type Result<T> = std::result::Result<T, CoreError>;
