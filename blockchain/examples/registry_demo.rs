//! 区块链交互层演示：部署合约 → 注册 DID → 签发方白名单 → 凭证哈希上链与撤销
//!
//! 运行前先启动本地 anvil 节点：
//!   anvil
//!
//! 然后：
//!   cargo run -p blockchain --example registry_demo

use blockchain::{ChainClient, credential_hash};
use ethers::types::Address;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
    // anvil 默认第一个账户私钥
    let private_key = std::env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".into()
    });

    println!("=== zkDID-Cred: 区块链交互层演示 ===\n");

    let client = ChainClient::connect(&rpc_url, &private_key).await?;
    println!("1. 已连接 RPC，签名者: {:?}\n", client.address());

    // 部署三个合约
    println!("2. 部署合约...");
    let did_registry = client.deploy_did_registry().await?;
    let issuer_registry = client.deploy_issuer_registry().await?;
    let vc_registry = client.deploy_vc_registry().await?;
    println!("   DIDRegistry:   {:?}", did_registry);
    println!("   IssuerRegistry:{:?}", issuer_registry);
    println!("   VCRegistry:   {:?}\n", vc_registry);

    // 3. 注册并解析 DID
    println!("3. DID 注册与解析...");
    let did = "did:key:z6MkStudent";
    client.register_did(did_registry, did).await?;
    let controller = client.resolve_did(did_registry, did).await?;
    println!("   resolve({did}) -> {controller:?}");
    assert_eq!(controller, client.address());
    println!("   ✓ 控制者与注册者一致\n");

    // 4. 签发方白名单
    println!("4. 签发方白名单...");
    let school: Address = Address::from_low_u64_be(0x5C001A);
    client
        .add_issuer(issuer_registry, school, "Beijing University")
        .await?;
    let authorized = client.is_authorized_issuer(issuer_registry, school).await?;
    println!("   is_authorized({school:?}) -> {authorized}");
    assert!(authorized);
    println!("   ✓ 学校已加入白名单\n");

    // 5. 凭证哈希上链 + 撤销
    println!("5. 凭证哈希上链与撤销...");
    let credential_json = r#"{"id":"urn:uuid:demo","gpa":3.85,"degree":"bachelor"}"#;
    let hash = credential_hash(credential_json.as_bytes());
    client.register_credential(vc_registry, hash, did).await?;
    println!("   已上链，keccak256 = 0x{}", hex::encode(hash));

    let revoked_before = client.is_revoked(vc_registry, hash).await?;
    println!("   is_revoked（撤销前）-> {revoked_before}");
    assert!(!revoked_before);

    client.revoke_credential(vc_registry, hash).await?;
    let revoked_after = client.is_revoked(vc_registry, hash).await?;
    println!("   is_revoked（撤销后）-> {revoked_after}");
    assert!(revoked_after);
    println!("   ✓ 撤销生效\n");

    println!("=== 演示完成 ===");
    Ok(())
}
