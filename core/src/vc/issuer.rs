//! 凭证签发：用签发方的 DID 私钥对凭证进行签名

use chrono::Utc;

use super::{PROOF_PURPOSE_ASSERTION, PROOF_TYPE_ED25519, Proof, VerifiableCredential};
use crate::crypto::KeyPair;
use crate::did::Did;
use crate::error::{CoreError, Result};

/// 生成签名所覆盖的凭证规范字节
///
/// proof 字段被排除，其余字段序列化为 JSON。Rust 结构体字段按声明顺序序列化，
/// 且 `serde_json` 的 map 默认按键排序，因此对相同输入结果是确定性的。
pub(crate) fn canonicalize(credential: &VerifiableCredential) -> Result<Vec<u8>> {
    let unsigned = credential.without_proof();
    serde_json::to_vec(&unsigned).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// 用签发方密钥对凭证签名，返回附带 [`Proof`] 的凭证
///
/// 签发方密钥对必须与凭证中记录的 `issuer` DID 对应，否则后续验证会失败。
///
/// # 错误
///
/// 当 `issuer` 字段不是合法 DID，或密钥对与签发方 DID 不匹配时返回错误。
pub fn issue_credential(
    mut credential: VerifiableCredential,
    issuer_keypair: &KeyPair,
) -> Result<VerifiableCredential> {
    // 签名所用私钥必须与签发方 DID 对应
    let issuer_did = Did::parse(&credential.issuer)?;
    let issuer_public = issuer_did.to_public_key()?;
    if issuer_public.to_bytes() != issuer_keypair.public.to_bytes() {
        return Err(CoreError::CryptoError(
            "Issuer key pair does not match the credential's issuer DID".to_string(),
        ));
    }

    // 对规范化（去除 proof）后的字节进行签名
    let message = canonicalize(&credential)?;
    let signature = issuer_keypair.sign(&message);
    let proof_value = bs58::encode(signature).into_string();

    // 验证方法指向签发方 DID 的断言密钥片段
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

    /// 测试：签发后凭证应附带正确的 proof
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

    /// 测试：用与签发方 DID 不匹配的密钥签发应失败
    #[test]
    fn test_issue_rejects_mismatched_key() {
        let issuer_kp = KeyPair::generate();
        let wrong_kp = KeyPair::generate();
        let holder_kp = KeyPair::generate();
        let issuer_did = Did::from_public_key(&issuer_kp.public).to_string();
        let holder_did = Did::from_public_key(&holder_kp.public).to_string();

        let vc = sample_credential(&issuer_did, &holder_did);
        // 用与签发方 DID 不匹配的密钥签名，必须失败
        assert!(issue_credential(vc, &wrong_kp).is_err());
    }
}
