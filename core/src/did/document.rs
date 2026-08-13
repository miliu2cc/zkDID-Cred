//! DID Document 的生成与（反）序列化
//!
//! 实现符合 W3C 规范的 `did:key` 方法 DID Document。
//! DID Document 描述了一个 DID 关联的公钥、认证方式等信息。

use serde::{Deserialize, Serialize};

use super::Did;
use crate::error::{CoreError, Result};

/// DID Core 规范的上下文 URI
const DID_CONTEXT_V1: &str = "https://www.w3.org/ns/did/v1";
/// Ed25519 2020 签名套件的上下文 URI
const ED25519_CONTEXT_2020: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
/// Ed25519 公钥对应的验证方法类型
const ED25519_VERIFICATION_KEY_2020: &str = "Ed25519VerificationKey2020";

/// DID Document 中的单个验证方法（Verification Method）
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// 完整限定 id，例如 "did:key:z6Mk...#z6Mk..."
    pub id: String,
    /// 密钥类型，例如 "Ed25519VerificationKey2020"
    #[serde(rename = "type")]
    pub type_: String,
    /// 控制该密钥的 DID
    pub controller: String,
    /// multibase 形式的公钥（与 did:key 标识符一致）
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// 符合 W3C 规范的 DID Document
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD 上下文
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// 本文档所描述的 DID
    pub id: String,
    /// 与该 DID 关联的公钥列表
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// 可用于身份认证（authentication）的验证方法引用
    pub authentication: Vec<String>,
    /// 可用于声明断言（assertionMethod，即 VC 签名）的验证方法引用
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
}

impl DidDocument {
    /// 从 `did:key` DID 构建 DID Document
    ///
    /// 对 `did:key` 而言，验证方法的片段（fragment）复用标识符本身，
    /// 因此完整的方法 id 形如 `did:key:z...#z...`。
    pub fn from_did(did: &Did) -> Self {
        let did_str = did.to_string();
        let identifier = did.identifier();
        let method_id = format!("{}#{}", did_str, identifier);

        let verification_method = VerificationMethod {
            id: method_id.clone(),
            type_: ED25519_VERIFICATION_KEY_2020.to_string(),
            controller: did_str.clone(),
            public_key_multibase: identifier.to_string(),
        };

        Self {
            context: vec![DID_CONTEXT_V1.to_string(), ED25519_CONTEXT_2020.to_string()],
            id: did_str,
            verification_method: vec![verification_method],
            authentication: vec![method_id.clone()],
            assertion_method: vec![method_id],
        }
    }

    /// 将文档序列化为带缩进的 JSON 字符串
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| CoreError::SerializationError(e.to_string()))
    }

    /// 从 JSON 字符串反序列化出文档
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| CoreError::DeserializationError(e.to_string()))
    }

    /// 按完整 id 查找验证方法
    pub fn get_verification_method(&self, id: &str) -> Option<&VerificationMethod> {
        self.verification_method.iter().find(|vm| vm.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    /// 测试：从 DID 生成的文档字段应正确
    #[test]
    fn test_document_from_did() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let doc = DidDocument::from_did(&did);

        assert_eq!(doc.id, did.to_string());
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].type_,
            ED25519_VERIFICATION_KEY_2020
        );
    }

    /// 测试：文档的 JSON 序列化/反序列化往返应保持一致
    #[test]
    fn test_document_json_roundtrip() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let doc = DidDocument::from_did(&did);

        let json = doc.to_json().unwrap();
        let restored = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc, restored);
    }

    /// 测试：按 id 查找验证方法，存在返回 Some，不存在返回 None
    #[test]
    fn test_get_verification_method() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let doc = DidDocument::from_did(&did);

        let method_id = &doc.verification_method[0].id;
        assert!(doc.get_verification_method(method_id).is_some());
        assert!(
            doc.get_verification_method("did:key:zNonExistent")
                .is_none()
        );
    }
}
