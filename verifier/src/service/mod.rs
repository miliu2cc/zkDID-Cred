//! 验证方服务逻辑：凭证验证

use serde::Serialize;
use zkdid_core::vc::VerifiableCredential;

/// 验证报告
#[derive(Serialize)]
pub struct VerifyReport {
    pub valid: bool,
    pub message: String,
    pub credential_id: String,
    pub issuer: String,
    pub subject: String,
    pub types: Vec<String>,
}

/// 验证凭证：检查签名、过期时间（撤销状态由区块链层负责）
pub fn verify(vc: &VerifiableCredential) -> VerifyReport {
    let report = VerifyReport {
        valid: false,
        message: String::new(),
        credential_id: vc.id.clone(),
        issuer: vc.issuer.clone(),
        subject: vc.credential_subject.id.clone(),
        types: vc.types.clone(),
    };

    match zkdid_core::vc::verify_credential(vc) {
        Ok(()) => VerifyReport {
            valid: true,
            message: "Credential is authentic and has not been tampered with".to_string(),
            ..report
        },
        Err(e) => VerifyReport {
            valid: false,
            message: e.to_string(),
            ..report
        },
    }
}
