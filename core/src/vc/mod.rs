//! 可验证凭证（VC，Verifiable Credential）模块
//!
//! 实现 W3C 可验证凭证数据模型的一个子集：
//! - 凭证数据结构（[`VerifiableCredential`]、[`CredentialSubject`]）
//! - 签发：签发方用其 DID 私钥对凭证签名（见 [`issuer`]）
//! - 验证：验证方通过签发方 DID 校验签名（见 [`verifier`]）
//!
//! 凭证一经签发即不可变。若需修改，应撤销旧凭证并重新签发新凭证
//! （见 [`CredentialStatus`]）。

pub mod issuer;
pub mod verifier;

pub use issuer::issue_credential;
pub use verifier::verify_credential;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// VC 的基础上下文 URI
pub const VC_CONTEXT_V1: &str = "https://www.w3.org/2018/credentials/v1";

/// 符合 W3C 规范的可验证凭证
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// JSON-LD 上下文
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// 凭证的唯一标识（如 UUID URN 或签发方 URL）
    pub id: String,

    /// 凭证类型，例如 ["VerifiableCredential", "UniversityDegreeCredential"]
    #[serde(rename = "type")]
    pub types: Vec<String>,

    /// 签发机构（学校）的 DID
    pub issuer: String,

    /// 签发时间戳（RFC3339 格式）
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    /// 可选的过期时间戳（RFC3339 格式）
    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,

    /// 关于凭证主体（学生）的声明内容
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,

    /// 可选的撤销 / 状态信息
    #[serde(rename = "credentialStatus", skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,

    /// 密码学证明。签名前为 `None`，签发后被填充
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

/// 凭证主体及其相关声明
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// 凭证主体（学生）的 DID
    pub id: String,

    /// 任意声明（如 gpa、degree、courses）。以 JSON 对象存储，
    /// 使不同类型的凭证可以携带不同字段
    #[serde(flatten)]
    pub claims: Value,
}

/// 凭证的撤销 / 状态信息
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredentialStatus {
    /// 状态条目 id（如撤销列表条目的 URL）
    pub id: String,
    /// 状态类型，例如 "RevocationList2020Status"
    #[serde(rename = "type")]
    pub type_: String,
}

/// 附加在凭证上的链接数据证明（linked-data proof）
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    /// 证明类型，例如 "Ed25519Signature2020"
    #[serde(rename = "type")]
    pub type_: String,
    /// 证明创建时间（RFC3339 格式）
    pub created: String,
    /// 产生该签名的验证方法（DID URL）
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    /// 证明用途，例如 "assertionMethod"
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    /// 分离式签名，采用 base58btc 编码
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// 本实现使用的证明类型字符串
pub const PROOF_TYPE_ED25519: &str = "Ed25519Signature2020";
/// 凭证签发默认使用的证明用途
pub const PROOF_PURPOSE_ASSERTION: &str = "assertionMethod";

impl VerifiableCredential {
    /// 返回一个清除了 `proof` 字段的凭证副本
    ///
    /// 这是被签名和验证的规范形式：签名覆盖除 proof 本身以外的所有字段。
    pub(crate) fn without_proof(&self) -> Self {
        let mut clone = self.clone();
        clone.proof = None;
        clone
    }
}
