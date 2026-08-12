//! Complete flow: generate DIDs, issue a credential, verify it.

use crate::std::error::{CoreError, Result};
use chrono::Utc;
use core::crypto::KeyPair;
use core::did::{Did, DidDocument, DidResolver, KeyMethodResolver};
use core::vc::{CredentialSubject, VerifiableCredential, issue_credential, verify_credential};
use serde_json::json;

fn main() -> core::Result<()> {
    println!("=== zkDID-Cred: Complete VC Flow ===\n");

    // Step 1: Generate key pairs for issuer (university) and holder (student).
    println!("1. Generating key pairs...");
    let issuer_keypair = KeyPair::generate();
    let holder_keypair = KeyPair::generate();
    println!("   ✓ Issuer and holder key pairs generated\n");

    // Step 2: Derive DIDs from public keys.
    println!("2. Creating DIDs...");
    let issuer_did = Did::from_public_key(&issuer_keypair.public);
    let holder_did = Did::from_public_key(&holder_keypair.public);
    println!("   Issuer DID:  {}", issuer_did);
    println!("   Holder DID:  {}\n", holder_did);

    // Step 3: Resolve DIDs to DID Documents.
    println!("3. Resolving DID Documents...");
    let resolver = KeyMethodResolver::new();
    let issuer_doc = resolver.resolve(&issuer_did.to_string())?;
    let holder_doc = resolver.resolve(&holder_did.to_string())?;
    println!("   ✓ Issuer document resolved");
    println!("   ✓ Holder document resolved\n");

    // Optional: print issuer's DID Document
    println!("   Issuer DID Document:");
    println!("{}\n", issuer_doc.to_json()?);

    // Step 4: Create an unsigned credential.
    println!("4. Creating credential...");
    let credential = VerifiableCredential {
        context: vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://example.edu/contexts/v1".to_string(),
        ],
        id: "urn:uuid:3d8c5f4a-9b2e-4c1d-8a7f-6e5d4c3b2a1b".to_string(),
        types: vec![
            "VerifiableCredential".to_string(),
            "UniversityDegreeCredential".to_string(),
        ],
        issuer: issuer_did.to_string(),
        issuance_date: Utc::now().to_rfc3339(),
        expiration_date: None,
        credential_subject: CredentialSubject {
            id: holder_did.to_string(),
            claims: json!({
                "name": "Alice Smith",
                "degree": "Bachelor of Computer Science",
                "gpa": 3.85,
                "graduationYear": 2024,
            }),
        },
        credential_status: None,
        proof: None,
    };
    println!("   ✓ Credential created (unsigned)\n");

    // Step 5: Issue the credential (sign it with issuer's key).
    println!("5. Issuing credential (signing)...");
    let signed_credential = issue_credential(credential, &issuer_keypair)?;
    println!("   ✓ Credential signed by issuer\n");

    println!("   Signed Credential:");
    println!("{}\n", serde_json::to_string_pretty(&signed_credential)?);

    // Step 6: Verify the credential.
    println!("6. Verifying credential...");
    verify_credential(&signed_credential)?;
    println!("   ✓ Credential signature is valid");
    println!("   ✓ Credential has not expired");
    println!("   ✓ Verification successful!\n");

    // Step 7: Demonstrate tampering detection.
    println!("7. Testing tampering detection...");
    let mut tampered = signed_credential.clone();
    tampered.credential_subject.claims = json!({
        "name": "Alice Smith",
        "degree": "Bachelor of Computer Science",
        "gpa": 4.0,  // Tampered: changed from 3.85 to 4.0
        "graduationYear": 2024,
    });
    match verify_credential(&tampered) {
        Ok(_) => println!("   ✗ Tampering not detected (should not happen!)"),
        Err(e) => println!("   ✓ Tampering detected: {}\n", e),
    }

    println!("=== Flow Complete ===");
    Ok(())
}
