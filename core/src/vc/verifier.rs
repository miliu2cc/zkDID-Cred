//! 凭证验证：对照签发方 DID 校验凭证的 proof

use chrono::{DateTime, Utc};

use super::{VerifiableCredential, issuer::canonicalize};
use crate::did::Did;
use crate::error::{CoreError, Result};

/// 验证凭证的 proof
///
/// 该函数会检查：
/// 1. 凭证是否携带 proof；
/// 2. 签名对由 `issuer` DID 派生出的公钥是否有效；
/// 3. 凭证是否已过期（若设置了 `expirationDate`）。
///
/// 该函数【不】检查撤销状态——撤销需要外部撤销列表 / 链上查询，
/// 由区块链层负责处理。
///
/// # 错误
///
/// 当 proof 缺失、格式非法、已过期，或签名验证失败时返回错误。
pub fn verify_credential(credential: &VerifiableCredential) -> Result<()> {
    let proof = credential
        .proof
        .as_ref()
        .ok_or_else(|| CoreError::SignatureVerificationFailed)?;

    // 从签发方 DID 还原其公钥
    let issuer_did = Did::parse(&credential.issuer)?;
    let issuer_public = issuer_did.to_public_key()?;

    // proof 的验证方法必须属于签发方 DID
    if !proof.verification_method.starts_with(&credential.issuer) {
        return Err(CoreError::CryptoError(
            "Proof verification method does not belong to the issuer DID".to_string(),
        ));
    }

    // 解码签名
    let signature = bs58::decode(&proof.proof_value)
        .into_vec()
        .map_err(|e| CoreError::DecodingError(format!("Signature decode failed: {}", e)))?;

    // 重建被签名的字节并验证签名
    let message = canonicalize(credential)?;
    issuer_public.verify(&message, &signature)?;

    // 若设置了过期时间则进行检查
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
                claims_commitment: None,
                claims: json!({ "gpa": 3.9 }),
            },
            credential_status: None,
            proof: None,
        };

        let signed = issue_credential(vc, &issuer_kp).unwrap();
        (signed, issuer_kp)
    }

    /// 测试：合法凭证应验证通过
    #[test]
    fn test_verify_valid_credential() {
        let (vc, _) = signed_credential();
        assert!(verify_credential(&vc).is_ok());
    }

    /// 测试：签名后篡改声明内容应导致验证失败
    #[test]
    fn test_verify_rejects_tampered_claims() {
        let (mut vc, _) = signed_credential();
        // 签名后篡改某个声明
        vc.credential_subject.claims = json!({ "gpa": 4.0 });
        assert!(verify_credential(&vc).is_err());
    }

    /// 测试：缺少 proof 的凭证应验证失败
    #[test]
    fn test_verify_rejects_missing_proof() {
        let (mut vc, _) = signed_credential();
        vc.proof = None;
        assert!(verify_credential(&vc).is_err());
    }

    /// 测试：签名有效但已过期的凭证应验证失败
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
                claims_commitment: None,
                claims: json!({ "gpa": 3.5 }),
            },
            credential_status: None,
            proof: None,
        };
        let signed = issue_credential(vc, &issuer_kp).unwrap();
        // 签名有效但凭证已过期
        assert!(verify_credential(&signed).is_err());
    }
}
