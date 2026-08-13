use thiserror::Error;

/// 核心库统一错误类型
#[derive(Error, Debug)]
pub enum CoreError {
    /// DID 格式非法（不符合 `did:method:identifier` 结构）
    #[error("Invalid DID format: {0}")]
    InvalidDidFormat(String),

    /// 不支持的 DID 方法（当前仅支持 `did:key`）
    #[error("Unsupported DID method: {0}")]
    UnsupportedMethod(String),

    /// 公钥非法（长度错误或无法解析）
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// 私钥非法（长度错误或无法解析）
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// 编码错误
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// 解码错误（如 Base58 / Hex 解码失败）
    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// 密码学操作错误
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// 签名验证失败
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// 序列化错误
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// 反序列化错误
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

/// 核心库统一使用的 Result 别名，错误类型固定为 [`CoreError`]
pub type Result<T> = std::result::Result<T, CoreError>;
