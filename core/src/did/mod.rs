//! DID（去中心化标识符）模块
//!
//! 实现基于 Ed25519 公钥的 `did:key` 方法。
//!
//! `did:key` 直接由公钥派生，无需链上注册或中心化服务：
//! ```text
//! did:key:z6Mk...
//!         │└─────── base58btc(multicodec 前缀 || 公钥字节)
//!         └──────── multibase 前缀 'z'（表示 base58btc 编码）
//! ```
//!
//! 对 Ed25519 而言，multicodec 前缀是 `0xed 0x01`（0xed 的无符号 varint 编码）。

pub mod document;
pub mod resolver;

pub use document::{DidDocument, VerificationMethod};
pub use resolver::{DidResolver, KeyMethodResolver};

use serde::{Deserialize, Serialize};

use crate::crypto::PublicKey;
use crate::error::{CoreError, Result};

/// Ed25519 公钥的 multicodec 前缀（0xed 的无符号 varint 编码）
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

/// base58btc 编码对应的 multibase 前缀字符
const MULTIBASE_BASE58BTC: char = 'z';

/// 使用 `did:key` 方法的去中心化标识符
///
/// # 示例
///
/// ```
/// use core::crypto::KeyPair;
/// use core::did::Did;
///
/// let keypair = KeyPair::generate();
/// let did = Did::from_public_key(&keypair.public);
/// assert!(did.to_string().starts_with("did:key:z"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Did {
    /// DID 方法名（例如 "key"）
    method: String,
    /// 方法特定的标识符（例如 "z6Mk..."）
    identifier: String,
}

impl Did {
    /// 由 Ed25519 公钥创建 `did:key` 类型的 DID
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        // 拼接：multicodec 前缀 || 公钥原始字节
        let mut bytes = Vec::with_capacity(2 + 32);
        bytes.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
        bytes.extend_from_slice(&public_key.to_bytes());

        // multibase 编码：'z' 前缀 + base58btc 编码
        let encoded = bs58::encode(&bytes).into_string();
        let identifier = format!("{}{}", MULTIBASE_BASE58BTC, encoded);

        Self {
            method: "key".to_string(),
            identifier,
        }
    }

    /// 将 DID 字符串解析为 `Did`
    ///
    /// # 错误
    ///
    /// 当 DID 格式非法或使用了不支持的方法时返回错误
    pub fn parse(did_str: &str) -> Result<Self> {
        // 按 ':' 拆分为最多 3 段：did、method、identifier
        let parts: Vec<&str> = did_str.splitn(3, ':').collect();

        if parts.len() != 3 {
            return Err(CoreError::InvalidDidFormat(format!(
                "Expected format 'did:method:identifier', got '{}'",
                did_str
            )));
        }

        // 第一段必须是固定的 "did"
        if parts[0] != "did" {
            return Err(CoreError::InvalidDidFormat(format!(
                "DID must start with 'did:', got '{}'",
                parts[0]
            )));
        }

        let method = parts[1].to_string();
        let identifier = parts[2].to_string();

        // 当前仅支持 did:key 方法
        if method != "key" {
            return Err(CoreError::UnsupportedMethod(method));
        }

        if identifier.is_empty() {
            return Err(CoreError::InvalidDidFormat(
                "Identifier cannot be empty".to_string(),
            ));
        }

        Ok(Self { method, identifier })
    }

    /// 从该 `did:key` 中还原出内嵌的 Ed25519 公钥
    ///
    /// # 错误
    ///
    /// 当标识符不是合法的 base58btc 编码的 Ed25519 multicodec 公钥时返回错误
    pub fn to_public_key(&self) -> Result<PublicKey> {
        // 第一个字符是 multibase 前缀，必须为 'z'
        let mut chars = self.identifier.chars();
        let prefix = chars
            .next()
            .ok_or_else(|| CoreError::InvalidDidFormat("Empty identifier".to_string()))?;

        if prefix != MULTIBASE_BASE58BTC {
            return Err(CoreError::InvalidDidFormat(format!(
                "Unsupported multibase prefix '{}', expected '{}'",
                prefix, MULTIBASE_BASE58BTC
            )));
        }

        // 去掉前缀后进行 base58 解码
        let encoded: String = chars.collect();
        let bytes = bs58::decode(&encoded)
            .into_vec()
            .map_err(|e| CoreError::DecodingError(format!("Base58 decode failed: {}", e)))?;

        // 解码结果应为 34 字节：2 字节 multicodec 前缀 + 32 字节公钥
        if bytes.len() != 34 {
            return Err(CoreError::InvalidPublicKey(format!(
                "Expected 34 bytes (2 prefix + 32 key), got {}",
                bytes.len()
            )));
        }

        // 校验 multicodec 前缀，确保确实是 Ed25519 公钥
        if bytes[0..2] != ED25519_MULTICODEC_PREFIX {
            return Err(CoreError::InvalidPublicKey(
                "Not an Ed25519 multicodec key".to_string(),
            ));
        }

        PublicKey::from_bytes(&bytes[2..])
    }

    /// 获取 DID 方法名
    pub fn method(&self) -> &str {
        &self.method
    }

    /// 获取方法特定的标识符
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.identifier)
    }
}

// 将 Did 序列化为其字符串形式（"did:key:z..."）
impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// 从字符串形式反序列化出 Did
impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Did::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    /// 测试：从公钥生成的 DID 应符合 did:key 格式
    #[test]
    fn test_did_generation() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        assert_eq!(did.method(), "key");
        assert!(did.to_string().starts_with("did:key:z"));
    }

    /// 测试：DID 字符串解析后应与原 DID 相等
    #[test]
    fn test_did_parse() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let did_str = did.to_string();

        let parsed = Did::parse(&did_str).unwrap();
        assert_eq!(parsed, did);
    }

    /// 测试：公钥 → DID → 公钥 的往返应保持一致
    #[test]
    fn test_did_roundtrip_public_key() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        let recovered = did.to_public_key().unwrap();
        assert_eq!(recovered.to_bytes(), keypair.public.to_bytes());
    }

    /// 测试：各种非法格式的 DID 都应解析失败
    #[test]
    fn test_parse_invalid_format() {
        assert!(Did::parse("not-a-did").is_err());
        assert!(Did::parse("did:key").is_err());
        assert!(Did::parse("foo:key:z123").is_err());
    }

    /// 测试：不支持的 DID 方法应返回 UnsupportedMethod 错误
    #[test]
    fn test_parse_unsupported_method() {
        let result = Did::parse("did:web:example.com");
        assert!(matches!(result, Err(CoreError::UnsupportedMethod(_))));
    }

    /// 测试：DID 的 JSON 序列化/反序列化往返应保持一致
    #[test]
    fn test_serde_roundtrip() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        let json = serde_json::to_string(&did).unwrap();
        let deserialized: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did, deserialized);
    }
}
