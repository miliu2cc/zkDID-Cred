//! 完整流程演示：签发带承诺的凭证 → 生成/验证 ZK 证明（绑定到凭证）
//!
//! 运行方式（确保 nargo / bb 在 PATH 中）：
//!   PATH="$HOME/.bb:$PATH" cargo run -p core --example zkp_demo

use chrono::Utc;
use core::crypto::KeyPair;
use core::did::Did;
use core::vc::{CredentialSubject, VerifiableCredential};
use core::zkp::{self, Claims};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> core::Result<()> {
    if !zkp::backend_available() {
        eprintln!("nargo / bb 未安装，跳过证明生成演示。");
        eprintln!("安装方式：noirup（nargo）+ bbup（bb）");
        return Ok(());
    }

    println!("=== zkDID-Cred: 完整流程演示 ===\n");

    // 1. 生成签发方（学校）与学生密钥对 + DID
    let issuer_kp = KeyPair::generate();
    let holder_kp = KeyPair::generate();
    let issuer_did = Did::from_public_key(&issuer_kp.public).to_string();
    let holder_did = Did::from_public_key(&holder_kp.public).to_string();
    println!("1. 签发方 DID: {}", issuer_did);
    println!("   学生 DID:   {}\n", holder_did);

    // 2. 构造凭证声明（ZK 兼容 schema：gpa / degree / courses）
    let credential = VerifiableCredential {
        context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
        id: "urn:uuid:demo-credential".to_string(),
        types: vec![
            "VerifiableCredential".to_string(),
            "UniversityDegreeCredential".to_string(),
        ],
        issuer: issuer_did.clone(),
        issuance_date: Utc::now().to_rfc3339(),
        expiration_date: None,
        credential_subject: CredentialSubject {
            id: holder_did.clone(),
            claims_commitment: None,
            claims: serde_json::json!({
                "gpa": 3.85,
                "degree": "bachelor",
                "major": "Computer Science",
                "courses": [101, 205]
            }),
        },
        credential_status: None,
        proof: None,
    };

    // 3. 签发：计算承诺并写入凭证，随后 Ed25519 签名
    println!("2. 签发凭证（计算承诺 + Ed25519 签名）...");
    let signed = zkp::issue_with_commitment(credential, &issuer_kp)?;
    let commitment = zkp::commitment_of_credential(&signed)?;
    println!("   ✓ 声明承诺: {}", commitment.to_hex());

    core::vc::verify_credential(&signed)?;
    println!("   ✓ 凭证签名有效\n");

    // 4. 学生侧：从凭证声明解析出电路声明
    let claims: Claims = zkp::claims_from_json(&signed.credential_subject.claims)?;

    // 5. 生成 GPA 证明（GPA > 3.5，不泄露具体分数）
    println!("3. 生成 GPA 证明（GPA > 3.5）...");
    let artifact = zkp::prove_gpa(&claims, 350)?;
    println!("   ✓ 证明已生成");

    // 6. 验证证明（绑定到凭证的签名承诺）
    println!("4. 验证证明（绑定到凭证承诺）...");
    zkp::verify(&artifact, Some(&commitment))?;
    println!("   ✓ 证明验证通过，且与凭证承诺一致");

    // 7. 防伪造：错误的承诺应被拒绝
    println!("\n5. 演示防伪造（错误承诺应被拒绝）...");
    let wrong = zkp::Fr::from_u64(0xdeadbeef);
    match zkp::verify(&artifact, Some(&wrong)) {
        Ok(_) => println!("   ✗ 不应通过（bug）"),
        Err(e) => println!("   ✓ 正确拒绝: {e}"),
    }

    println!("\n=== 演示完成 ===");
    Ok(())
}
