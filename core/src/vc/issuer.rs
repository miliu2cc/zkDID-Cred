//! Credential issuance: signing a credential with the issuer's DID key.

use chrono::Utc;

use super::{PROOF_PURPOSE_ASSERTION, PROOF_TYPE_ED25519, Proof, VerifiableCredential};
use crate::crypto::KeyPair;
use crate::did::Did;
use crate::error::{CoreError, Result};

/// Produce the canonical bytes of a credential that the signature covers.
///
/// The proof field is excluded; every other field is serialized to JSON. Rust
/// struct fields serialize in declaration order and `serde_json` maps have
/// sorted keys by default, so this is deterministic for the same input.
pub(crate) fn canonicalize(credential: &VerifiableCredential) -> Result<Vec<u8>> {
    let unsigned = credential.without_proof();
    serde_json::to_vec(&unsigned).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// Sign a credential with the issuer's key pair, returning a credential with an
/// attached [`Proof`].
///
/// The issuer key pair must correspond to the `issuer` DID recorded in the
/// credential; otherwise verification will later fail.
///
/// # Errors
///
/// Returns an error if the `issuer` field is not a valid DID or if the key pair
/// does not match the issuer DID.
pub fn issue_credential(
    mut credential: VerifiableCredential,
    issuer_keypair: &KeyPair,
) -> Result<VerifiableCredential> {
    // The signing key must match the issuer DID.
    let issuer_did = Did::parse(&credential.issuer)?;
    let issuer_public = issuer_did.to_public_key()?;
    if issuer_public.to_bytes() != issuer_keypair.public.to_bytes() {
        return Err(CoreError::CryptoError(
            "Issuer key pair does not match the credential's issuer DID".to_string(),
        ));
    }

    // Sign the canonical (proof-less) bytes.
    let message = canonicalize(&credential)?;
    let signature = issuer_keypair.sign(&message);
    let proof_value = bs58::encode(signature).into_string();

    // The verification method is the issuer DID's assertion key fragment.
    let verification_method = format!("{}#{}", issuer_did, issuer_did.identifier());

    credential.proof = Some(Proof {
        type_: PROOF_TYPE_ED25519.to_string(),
        created: Utc::now().to_rfc3339(),
        verification_method,
        proof_purpose: PROOF_PURPOSE_ASSERTION.to_string(),
        proof_value,
    });

    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vc::CredentialSubject;
    use serde_json::json;

    fn sample_credential(issuer_did: &str, holder_did: &str) -> VerifiableCredential {
        VerifiableCredential {
            context: vec![crate::vc::VC_CONTEXT_V1.to_string()],
            id: "urn:uuid:test-credential-1".to_string(),
            types: vec![
                "VerifiableCredential".to_string(),
                "UniversityDegreeCredential".to_string(),
            ],
            issuer: issuer_did.to_string(),
            issuance_date: Utc::now().to_rfc3339(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: holder_did.to_string(),
                claims: json!({ "gpa": 3.8, "degree": "Computer Science" }),
            },
            credential_status: None,
            proof: None,
        }
    }

    #[test]
    fn test_issue_attaches_proof() {
        let issuer_kp = KeyPair::generate();
        let holder_kp = KeyPair::generate();
        let issuer_did = Did::from_public_key(&issuer_kp.public).to_string();
        let holder_did = Did::from_public_key(&holder_kp.public).to_string();

        let vc = sample_credential(&issuer_did, &holder_did);
        let signed = issue_credential(vc, &issuer_kp).unwrap();

        assert!(signed.proof.is_some());
        let proof = signed.proof.unwrap();
        assert_eq!(proof.type_, PROOF_TYPE_ED25519);
        assert_eq!(proof.proof_purpose, PROOF_PURPOSE_ASSERTION);
        assert!(!proof.proof_value.is_empty());
    }

    #[test]
    fn test_issue_rejects_mismatched_key() {
        let issuer_kp = KeyPair::generate();
        let wrong_kp = KeyPair::generate();
        let holder_kp = KeyPair::generate();
        let issuer_did = Did::from_public_key(&issuer_kp.public).to_string();
        let holder_did = Did::from_public_key(&holder_kp.public).to_string();

        let vc = sample_credential(&issuer_did, &holder_did);
        // Signing with a key that doesn't match the issuer DID must fail.
        assert!(issue_credential(vc, &wrong_kp).is_err());
    }
}
