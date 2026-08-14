//! 密码学模块
//!
//! 基于 Ed25519 签名算法，提供密钥对生成、签名、验证，
//! 以及公私钥在 Base58 / Hex / 原始字节之间的编解码能力。
//! Ed25519 签名速度快、签名体积小（64 字节），是 DID 与 VC 的密码学基础。

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{CoreError, Result};

/// Ed25519 密钥对，包含用于验证的公钥和用于签名的私钥
#[derive(Clone)]
pub struct KeyPair {
    /// 公钥
    pub public: PublicKey,
    /// 私钥（保密）
    pub secret: SecretKey,
}

/// Ed25519 公钥
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

/// Ed25519 私钥
#[derive(Clone)]
pub struct SecretKey(SigningKey);

// 为 PublicKey 自定义 Serialize：底层 VerifyingKey 未实现 serde，
// 这里将其序列化为原始 32 字节
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

// 为 PublicKey 自定义 Deserialize：从字节数组还原公钥
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        PublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl KeyPair {
    /// 生成一个全新的随机密钥对
    ///
    /// # 示例
    ///
    /// ```
    /// use zkdid_core::crypto::KeyPair;
    ///
    /// let keypair = KeyPair::generate();
    /// ```
    pub fn generate() -> Self {
        // 用密码学安全随机数生成 32 字节私钥种子，再派生出公钥
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key = signing_key.verifying_key();

        Self {
            public: PublicKey(verifying_key),
            secret: SecretKey(signing_key),
        }
    }

    /// 从原始字节还原密钥对
    ///
    /// # 参数
    ///
    /// * `secret_bytes` - 32 字节的私钥
    ///
    /// # 错误
    ///
    /// 当私钥字节长度不正确时返回错误
    pub fn from_secret_bytes(secret_bytes: &[u8]) -> Result<Self> {
        if secret_bytes.len() != 32 {
            return Err(CoreError::InvalidSecretKey(
                "Secret key must be 32 bytes".to_string(),
            ));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret_bytes);

        // 由私钥重新派生公钥，保证公私钥一致
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            public: PublicKey(verifying_key),
            secret: SecretKey(signing_key),
        })
    }

    /// 获取私钥的原始字节
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.0.to_bytes()
    }

    /// 用该密钥对私钥对消息进行签名
    ///
    /// # 参数
    ///
    /// * `message` - 待签名的消息
    ///
    /// # 返回
    ///
    /// 64 字节的签名
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature: Signature = self.secret.0.sign(message);
        signature.to_bytes()
    }

    /// 将私钥编码为 Base58 字符串（用于持久化存储）
    pub fn secret_to_base58(&self) -> String {
        bs58::encode(self.secret_bytes()).into_string()
    }

    /// 从 Base58 编码的私钥字符串还原密钥对
    pub fn from_base58_secret(encoded: &str) -> Result<Self> {
        let bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| CoreError::DecodingError(format!("Base58 decode failed: {}", e)))?;

        Self::from_secret_bytes(&bytes)
    }
}

impl PublicKey {
    /// 从原始字节创建公钥
    ///
    /// # 参数
    ///
    /// * `bytes` - 32 字节的公钥
    ///
    /// # 错误
    ///
    /// 当公钥字节非法时返回错误
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CoreError::InvalidPublicKey(
                "Public key must be 32 bytes".to_string(),
            ));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CoreError::InvalidPublicKey(format!("Invalid key bytes: {}", e)))?;

        Ok(Self(verifying_key))
    }

    /// 获取公钥的原始字节
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// 将公钥编码为 Base58 字符串
    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    /// 从 Base58 编码字符串创建公钥
    pub fn from_base58(encoded: &str) -> Result<Self> {
        let bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|e| CoreError::DecodingError(format!("Base58 decode failed: {}", e)))?;

        Self::from_bytes(&bytes)
    }

    /// 将公钥编码为十六进制字符串
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// 从十六进制字符串创建公钥
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CoreError::DecodingError(format!("Hex decode failed: {}", e)))?;

        Self::from_bytes(&bytes)
    }

    /// 验证消息上的签名
    ///
    /// # 参数
    ///
    /// * `message` - 被签名的原始消息
    /// * `signature` - 待验证的 64 字节签名
    ///
    /// # 返回
    ///
    /// 签名有效返回 `Ok(())`，否则返回错误
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != 64 {
            return Err(CoreError::SignatureVerificationFailed);
        }

        let sig = Signature::from_bytes(signature.try_into().unwrap());

        self.0
            .verify(message, &sig)
            .map_err(|_| CoreError::SignatureVerificationFailed)
    }
}

impl SecretKey {
    /// 获取私钥的原始字节
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

// 为 SecretKey 自定义 Debug，避免在日志或调试输出中泄露私钥内容
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        assert_eq!(keypair.public.to_bytes().len(), 32);
        assert_eq!(keypair.secret_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let message = b"Hello, World!";

        let signature = keypair.sign(message);
        assert_eq!(signature.len(), 64);

        // 正确的消息和签名应验证成功
        assert!(keypair.public.verify(message, &signature).is_ok());

        // 消息被篡改时验证应失败
        let wrong_message = b"Wrong message";
        assert!(keypair.public.verify(wrong_message, &signature).is_err());

        // 签名错误时验证应失败
        let wrong_signature = [0u8; 64];
        assert!(keypair.public.verify(message, &wrong_signature).is_err());
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = KeyPair::generate();
        let secret_bytes = keypair.secret_bytes();

        // 从字节还原密钥对
        let restored_keypair = KeyPair::from_secret_bytes(&secret_bytes).unwrap();

        assert_eq!(
            keypair.public.to_bytes(),
            restored_keypair.public.to_bytes()
        );
        assert_eq!(keypair.secret_bytes(), restored_keypair.secret_bytes());
    }

    #[test]
    fn test_base58_encoding() {
        let keypair = KeyPair::generate();

        // 测试公钥编解码往返
        let public_base58 = keypair.public.to_base58();
        let restored_public = PublicKey::from_base58(&public_base58).unwrap();
        assert_eq!(keypair.public.to_bytes(), restored_public.to_bytes());

        // 测试私钥编解码往返
        let secret_base58 = keypair.secret_to_base58();
        let restored_keypair = KeyPair::from_base58_secret(&secret_base58).unwrap();
        assert_eq!(
            keypair.public.to_bytes(),
            restored_keypair.public.to_bytes()
        );
    }

    #[test]
    fn test_hex_encoding() {
        let keypair = KeyPair::generate();

        let hex = keypair.public.to_hex();
        let restored = PublicKey::from_hex(&hex).unwrap();

        assert_eq!(keypair.public.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_invalid_key_lengths() {
        // 公钥长度非法应报错
        let invalid_public = PublicKey::from_bytes(&[0u8; 16]);
        assert!(invalid_public.is_err());

        // 私钥长度非法应报错
        let invalid_secret = KeyPair::from_secret_bytes(&[0u8; 16]);
        assert!(invalid_secret.is_err());
    }

    #[test]
    fn test_signature_verification_with_different_keypair() {
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let message = b"Test message";

        let signature = keypair1.sign(message);

        // 用正确的公钥验证应成功
        assert!(keypair1.public.verify(message, &signature).is_ok());

        // 用另一个密钥对的公钥验证应失败
        assert!(keypair2.public.verify(message, &signature).is_err());
    }
}
