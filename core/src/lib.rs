//! # zkDID-Cred Core Library
//!
//! Core functionality for DID (Decentralized Identifiers) and Verifiable Credentials
//! with zero-knowledge proof capabilities.
//!
//! ## Modules
//!
//! - `crypto`: Cryptographic primitives (Ed25519 key pairs, signing, verification)
//! - `did`: DID generation, parsing, and resolution
//! - `error`: Error types and result aliases

//! Core library for zkDID-Cred: DID generation, VC issuance, and verification.

pub mod crypto;
pub mod did;
pub mod error;
pub mod vc;

// Re-export commonly used types
pub use error::{CoreError, Result};
