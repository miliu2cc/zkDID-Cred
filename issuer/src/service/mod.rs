//! 学校端服务逻辑：身份管理与凭证签发

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use zkdid_core::crypto::KeyPair;
use zkdid_core::did::Did;
use zkdid_core::vc::{CredentialSubject, VerifiableCredential};

/// 签发方身份（持久化到 ~/.zkdid-issuer/identity.json）
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuerIdentity {
    pub name: String,
    pub did: String,
    pub secret_key: String,
}

/// 签发方数据目录
pub fn issuer_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
    let dir = home.join(".zkdid-issuer");
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

fn identity_path() -> Result<PathBuf> {
    Ok(issuer_dir()?.join("identity.json"))
}

/// 初始化身份（若已存在则返回现有身份）
pub fn init_identity(name: &str) -> Result<IssuerIdentity> {
    let path = identity_path()?;
    if path.exists() {
        let content = fs::read_to_string(&path)?;
        return Ok(serde_json::from_str(&content)?);
    }

    let keypair = KeyPair::generate();
    let did = Did::from_public_key(&keypair.public);
    let identity = IssuerIdentity {
        name: name.to_string(),
        did: did.to_string(),
        secret_key: keypair.secret_to_base58(),
    };
    fs::write(&path, serde_json::to_string_pretty(&identity)?)?;
    Ok(identity)
}

/// 加载已存在的身份
pub fn load_identity() -> Result<IssuerIdentity> {
    let path = identity_path()?;
    if !path.exists() {
        anyhow::bail!("Issuer identity not found. Call /init first.");
    }
    let content = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&content)?)
}

/// 签发凭证：计算声明承诺（Poseidon2）并签名
pub fn issue(
    identity: &IssuerIdentity,
    holder: &str,
    credential_type: &str,
    claims: serde_json::Value,
    expiration: Option<String>,
) -> Result<VerifiableCredential> {
    let keypair = KeyPair::from_base58_secret(&identity.secret_key)?;

    let credential = VerifiableCredential {
        context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        types: vec![
            "VerifiableCredential".to_string(),
            credential_type.to_string(),
        ],
        issuer: identity.did.clone(),
        issuance_date: Utc::now().to_rfc3339(),
        expiration_date: expiration,
        credential_subject: CredentialSubject {
            id: holder.to_string(),
            claims_commitment: None,
            claims,
        },
        credential_status: None,
        proof: None,
    };

    Ok(zkdid_core::zkp::issue_with_commitment(
        credential, &keypair,
    )?)
}
