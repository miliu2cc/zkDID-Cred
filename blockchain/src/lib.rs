//! 区块链交互层
//!
//! 基于 ethers-rs 封装 DID / Issuer / VC 三个 Registry 合约，
//! 提供 DID 注册与解析、签发方白名单、凭证哈希上链与撤销查询。
//!
//! 需要连接一个 EVM 节点（本地 anvil 或 Polygon 测试网）。

use std::sync::Arc;

use ethers::contract::abigen;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Middleware, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::Address;

pub type Result<T> = anyhow::Result<T>;

// 生成三个合约的类型安全绑定（含部署字节码）
abigen!(DIDRegistry, "abi/DIDRegistry.json");
abigen!(IssuerRegistry, "abi/IssuerRegistry.json");
abigen!(VCRegistry, "abi/VCRegistry.json");

/// 签名客户端类型别名
pub type Client = SignerMiddleware<Provider<Http>, LocalWallet>;

/// 区块链客户端：封装 provider + signer，以及三个合约的交互
#[derive(Clone)]
pub struct ChainClient {
    client: Arc<Client>,
}

impl ChainClient {
    /// 通过 RPC 地址和私钥连接（私钥为 0x 前缀十六进制）
    pub async fn connect(rpc_url: &str, private_key: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let chain_id = provider.get_chainid().await?;
        let wallet = private_key
            .parse::<LocalWallet>()?
            .with_chain_id(chain_id.as_u64());
        let client = SignerMiddleware::new(provider, wallet);
        Ok(Self {
            client: Arc::new(client),
        })
    }

    /// 当前签名者地址
    pub fn address(&self) -> Address {
        self.client.address()
    }

    /// 底层客户端引用
    pub fn inner(&self) -> Arc<Client> {
        self.client.clone()
    }

    // ------------------------------------------------------------------
    // 部署
    // ------------------------------------------------------------------

    pub async fn deploy_did_registry(&self) -> Result<Address> {
        Ok(DIDRegistry::deploy(self.client.clone(), ())?
            .send()
            .await?
            .address())
    }

    pub async fn deploy_issuer_registry(&self) -> Result<Address> {
        Ok(IssuerRegistry::deploy(self.client.clone(), ())?
            .send()
            .await?
            .address())
    }

    pub async fn deploy_vc_registry(&self) -> Result<Address> {
        Ok(VCRegistry::deploy(self.client.clone(), ())?
            .send()
            .await?
            .address())
    }

    // ------------------------------------------------------------------
    // DID Registry
    // ------------------------------------------------------------------

    /// 注册 DID（调用者成为控制者）
    pub async fn register_did(&self, registry: Address, did: &str) -> Result<()> {
        let c = DIDRegistry::new(registry, self.client.clone());
        let _ = c.register_did(did.to_string()).send().await?.await?;
        Ok(())
    }

    /// 解析 DID → 控制者地址
    pub async fn resolve_did(&self, registry: Address, did: &str) -> Result<Address> {
        let c = DIDRegistry::new(registry, self.client.clone());
        Ok(c.resolve_did(did.to_string()).call().await?)
    }

    /// 注销 DID
    pub async fn deactivate_did(&self, registry: Address, did: &str) -> Result<()> {
        let c = DIDRegistry::new(registry, self.client.clone());
        let _ = c.deactivate_did(did.to_string()).send().await?.await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Issuer Registry
    // ------------------------------------------------------------------

    /// 添加授权签发方（学校），仅 owner 可调用
    pub async fn add_issuer(&self, registry: Address, issuer: Address, name: &str) -> Result<()> {
        let c = IssuerRegistry::new(registry, self.client.clone());
        let _ = c.add_issuer(issuer, name.to_string()).send().await?.await?;
        Ok(())
    }

    /// 查询某地址是否为授权签发方
    pub async fn is_authorized_issuer(&self, registry: Address, issuer: Address) -> Result<bool> {
        let c = IssuerRegistry::new(registry, self.client.clone());
        Ok(c.is_authorized(issuer).call().await?)
    }

    // ------------------------------------------------------------------
    // VC Registry
    // ------------------------------------------------------------------

    /// 凭证哈希上链（防篡改时间戳）
    pub async fn register_credential(
        &self,
        registry: Address,
        hash: [u8; 32],
        subject_did: &str,
    ) -> Result<()> {
        let c = VCRegistry::new(registry, self.client.clone());
        let _ = c
            .register_credential(hash, subject_did.to_string())
            .send()
            .await?
            .await?;
        Ok(())
    }

    /// 撤销凭证（仅签发方可调用）
    pub async fn revoke_credential(&self, registry: Address, hash: [u8; 32]) -> Result<()> {
        let c = VCRegistry::new(registry, self.client.clone());
        let _ = c.revoke_credential(hash).send().await?.await?;
        Ok(())
    }

    /// 查询凭证是否已被撤销
    pub async fn is_revoked(&self, registry: Address, hash: [u8; 32]) -> Result<bool> {
        let c = VCRegistry::new(registry, self.client.clone());
        Ok(c.is_revoked(hash).call().await?)
    }
}

/// 计算凭证哈希（keccak256，与链上 VCRegistry 对应）
pub fn credential_hash(data: &[u8]) -> [u8; 32] {
    ethers::utils::keccak256(data)
}
