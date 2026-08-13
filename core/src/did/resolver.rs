//! DID 解析（Resolution）
//!
//! 对 `did:key` 而言，解析完全在本地完成：DID Document 直接
//! 由 DID 中内嵌的公钥重建，无需任何网络或链上查询。

use super::{Did, DidDocument};
use crate::error::Result;

/// 解析器：将 DID 字符串转换为 DID Document
pub trait DidResolver {
    /// 将 DID 字符串解析为对应的 DID Document
    fn resolve(&self, did_str: &str) -> Result<DidDocument>;
}

/// `did:key` 方法的解析器
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyMethodResolver;

impl KeyMethodResolver {
    /// 创建一个新的 `did:key` 解析器
    pub fn new() -> Self {
        Self
    }
}

impl DidResolver for KeyMethodResolver {
    fn resolve(&self, did_str: &str) -> Result<DidDocument> {
        // 解析过程会校验方法名，并确认标识符能解码出合法的 Ed25519 公钥
        let did = Did::parse(did_str)?;
        did.to_public_key()?;
        Ok(DidDocument::from_did(&did))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    /// 测试：解析合法 DID，文档 id 应与输入一致
    #[test]
    fn test_resolve_valid_did() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);
        let did_str = did.to_string();

        let resolver = KeyMethodResolver::new();
        let doc = resolver.resolve(&did_str).unwrap();

        assert_eq!(doc.id, did_str);
    }

    /// 测试：解析非法或不支持的 DID 应失败
    #[test]
    fn test_resolve_invalid_did() {
        let resolver = KeyMethodResolver::new();
        assert!(resolver.resolve("did:web:example.com").is_err());
        assert!(resolver.resolve("not-a-did").is_err());
    }

    /// 测试：解析出的文档中公钥应与 DID 标识符一致
    #[test]
    fn test_resolve_matches_public_key() {
        let keypair = KeyPair::generate();
        let did = Did::from_public_key(&keypair.public);

        let resolver = KeyMethodResolver::new();
        let doc = resolver.resolve(&did.to_string()).unwrap();

        // 验证方法中的 multibase 公钥应与 DID 标识符一致
        assert_eq!(
            doc.verification_method[0].public_key_multibase,
            did.identifier()
        );
    }
}
