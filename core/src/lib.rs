//! # zkDID-Cred 核心库
//!
//! 提供去中心化标识符（DID）与可验证凭证（VC）的核心功能，
//! 并为后续的零知识证明能力打下基础。
//!
//! ## 模块说明
//!
//! - `crypto`：密码学原语（Ed25519 密钥对、签名、验证）
//! - `did`：DID 的生成、解析与解析器
//! - `vc`：可验证凭证的数据结构、签发与验证
//! - `error`：错误类型与 Result 别名

pub mod crypto;
pub mod did;
pub mod error;
pub mod vc;

// 重新导出常用类型，方便外部直接 `use core::{CoreError, Result}`
pub use error::{CoreError, Result};
