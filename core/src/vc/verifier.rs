//! Credential verification: checking a credential's proof against the issuer DID.

use chrono::{DateTime, Utc};

use super::{VerifiableCredential, issuer::canonicalize};
use crate::did::Did;
use crate::error::{CoreError, Result};

/// Verify a credential's proof.
///
/// This checks that:
/// 1. The credential carries a proof.
/// 2. The signature is valid for the public key derived from the `issuer` DID.
/// 3. The credential has not expired (if `expirationDate` is set).
///
/// It does NOT check revocation status — that requires an external revocation
/// list / on-chain lookup and is handled by the blockchain layer.
///
/// # Errors
///
/// Returns an error if the proof is missing, malformed, expired, or if the
/// signature does not verify.
pub fn verify_credential(credential: &VerifiableCredential) -> Result<()> {
    let proof = credential
        .proof
        .as_ref()
        .ok_or_else(|| CoreError::SignatureVerificationFailed)?;

    // Recover the issuer's public key from the issuer DID.
    let issuer_did = Did::parse(&credential.issuer)?;
    let issuer_public = issuer_did.to_public_key()?;

    // The proof's verification method must belong to the issuer DID.
    if !proof.verification_method.starts_with(&credential.issuer) {
        return Err(CoreError::CryptoError(
            "Proof verification method does not belong to the issuer DID".to_string(),
        ));
    }

    // Decode the signature.
    let signature = bs58::decode(&proof.proof_value)
        .into_vec()
        .map_err(|e| CoreError::DecodingError(format!("Signature decode failed: {}", e)))?;

    // Reconstruct the signed bytes and verify.
    let message = canonicalize(credential)?;
    issuer_public.verify(&message, &signature)?;

    // Check expiration if present.
    if let Some(exp) = &credential.expiration_date {
        let exp_time = DateTime::parse_from_rfc3339(exp)
            .map_err(|e| CoreError::DeserializationError(format!("Invalid expirationDate: {}", e)))?
            .with_timezone(&Utc);
        if Utc::now() > exp_time {
            return Err(CoreError::CryptoError("Credential has expired".to_string()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::vc::{CredentialSubject, VC_CONTEXT_V1, VerifiableCredential, issue_credential};
    use serde_json::json;

    fn signed_credential() -> (VerifiableCredential, KeyPair) {
        let issuer_kp = KeyPair::generate();
        let holder_kp = KeyPair::generate();
        let issuer_did = Did::from_public_key(&issuer_kp.public).to_string();
        let holder_did = Did::from_public_key(&holder_kp.public).to_string();

        let vc = VerifiableCredential {
            context: vec![VC_CONTEXT_V1.to_string()],
            id: "urn:uuid:test-credential-2".to_string(),
            types: vec!["VerifiableCredential".to_string()],
            issuer: issuer_did,
            issuance_date: Utc::now().to_rfc3339(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: holder_did,
                claims: json!({ "gpa": 3.9 }),
            },
            credential_status: None,
            proof: None,
        };

        let signed = issue_credential(vc, &issuer_kp).unwrap();
        (signed, issuer_kp)
    }

    #[test]
    fn test_verify_valid_credential() {
        let (vc, _) = signed_credential();
        assert!(verify_credential(&vc).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_claims() {
        let (mut vc, _) = signed_credential();
        // Tamper with a claim after signing.
        vc.credential_subject.claims = json!({ "gpa": 4.0 });
        assert!(verify_credential(&vc).is_err());
    }

    #[test]
    fn test_verify_rejects_missing_proof() {
        let (mut vc, _) = signed_credential();
        vc.proof = None;
        assert!(verify_credential(&vc).is_err());
    }

    #[test]
    fn test_verify_rejects_expired_credential() {
        let issuer_kp = KeyPair::generate();
        let holder_kp = KeyPair::generate();
        let issuer_did = Did::from_public_key(&issuer_kp.public).to_string();
        let holder_did = Did::from_public_key(&holder_kp.public).to_string();

        let vc = VerifiableCredential {
            context: vec![VC_CONTEXT_V1.to_string()],
            id: "urn:uuid:expired".to_string(),
            types: vec!["VerifiableCredential".to_string()],
            issuer: issuer_did,
            issuance_date: "2020-01-01T00:00:00Z".to_string(),
            expiration_date: Some("2021-01-01T00:00:00Z".to_string()),
            credential_subject: CredentialSubject {
                id: holder_did,
                claims: json!({ "gpa": 3.5 }),
            },
            credential_status: None,
            proof: None,
        };
        let signed = issue_credential(vc, &issuer_kp).unwrap();
        // Signature is valid but the credential is expired.
        assert!(verify_credential(&signed).is_err());
    }
}
