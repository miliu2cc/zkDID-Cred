//! 完整流程演示：生成 DID、签发凭证、验证凭证

use chrono::Utc;
use serde_json::json;
use zkdid_core::crypto::KeyPair;
use zkdid_core::did::{Did, DidResolver, KeyMethodResolver};
use zkdid_core::vc::{
    CredentialSubject, VerifiableCredential, issue_credential, verify_credential,
};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> zkdid_core::Result<()> {
    println!("=== zkDID-Cred: Complete VC Flow ===\n");

    // 步骤 1：为签发方（大学）和持有方（学生）生成密钥对
    println!("1. 生成密钥对...");
    let issuer_keypair = KeyPair::generate();
    let holder_keypair = KeyPair::generate();
    println!("   ✓ 签发方和持有方的密钥对已生成\n");

    // 步骤 2：从公钥派生 DID
    println!("2. 创建 DID...");
    let issuer_did = Did::from_public_key(&issuer_keypair.public);
    let holder_did = Did::from_public_key(&holder_keypair.public);
    println!("   签发方 DID:  {}", issuer_did);
    println!("   持有方 DID:  {}\n", holder_did);

    // 步骤 3：解析 DID 为 DID Document
    println!("3. 解析 DID Document...");
    let resolver = KeyMethodResolver::new();
    let issuer_doc = resolver.resolve(&issuer_did.to_string())?;
    let _holder_doc = resolver.resolve(&holder_did.to_string())?;
    println!("   ✓ 签发方文档已解析");
    println!("   ✓ 持有方文档已解析\n");

    // 可选：打印签发方的 DID Document
    println!("   签发方 DID Document:");
    println!("{}\n", issuer_doc.to_json()?);

    // 步骤 4：创建未签名的凭证
    println!("4. 创建凭证...");
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
            claims_commitment: None,
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
    println!("   ✓ 凭证已创建（未签名）\n");

    // 步骤 5：签发凭证（用签发方的密钥签名）
    println!("5. 签发凭证（签名中）...");
    let signed_credential = issue_credential(credential, &issuer_keypair)?;
    println!("   ✓ 凭证已由签发方签名\n");

    println!("   已签名的凭证:");
    let json_str = serde_json::to_string_pretty(&signed_credential)
        .map_err(|e| zkdid_core::CoreError::SerializationError(e.to_string()))?;
    println!("{}\n", json_str);

    // 步骤 6：验证凭证
    println!("6. 验证凭证...");
    verify_credential(&signed_credential)?;
    println!("   ✓ 凭证签名有效");
    println!("   ✓ 凭证未过期");
    println!("   ✓ 验证成功！\n");

    // 步骤 7：演示篡改检测
    println!("7. 测试篡改检测...");
    let mut tampered = signed_credential.clone();
    tampered.credential_subject.claims = json!({
        "name": "Alice Smith",
        "degree": "Bachelor of Computer Science",
        "gpa": 4.0,  // 篡改：从 3.85 改为 4.0
        "graduationYear": 2024,
    });
    match verify_credential(&tampered) {
        Ok(_) => println!("   ✗ 未检测到篡改（不应发生！）"),
        Err(e) => println!("   ✓ 检测到篡改: {}\n", e),
    }

    println!("=== 流程完成 ===");
    Ok(())
}
