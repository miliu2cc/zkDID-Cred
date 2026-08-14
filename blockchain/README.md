# 区块链交互层（blockchain）

基于 [ethers-rs](https://github.com/gakonst/ethers-rs) 封装三个智能合约，
提供链上可信基础设施：

- **DID Registry**：DID 注册、解析、注销
- **Issuer Registry**：学校（签发方）白名单
- **VC Registry**：凭证哈希上链（防篡改时间戳）与撤销查询

## 目录

- `src/lib.rs` — `ChainClient` 客户端 + 三个合约的类型安全绑定（`abigen!`）
- `abi/*.json` — 合约 ABI + 字节码（由 `contracts/out` 生成，供 abigen 使用）
- `examples/registry_demo.rs` — 端到端演示

## 使用

```bash
# 1. 启动本地节点
anvil

# 2. 运行演示（部署合约 + 注册 DID + 白名单 + 凭证哈希上链/撤销）
cargo run -p blockchain --example registry_demo

# 连接自定义 RPC（如 Polygon 测试网）
RPC_URL=https://rpc-mumbai.maticvigil.com cargo run -p blockchain --example registry_demo
```

## 重新生成 ABI

当 `contracts` 中的 Solidity 合约改动后，需要重新生成 `abi/*.json`：

```bash
cd contracts && forge build
python3 - <<'EOF'
import json, os
for c in ['DIDRegistry', 'IssuerRegistry', 'VCRegistry']:
    a = json.load(open(f'out/{c}.sol/{c}.json'))
    raw = a['bytecode']['object']
    if raw.startswith('0x'): raw = raw[2:]
    json.dump({'abi': a['abi'], 'bytecode': '0x'+raw}, open(f'../blockchain/abi/{c}.json','w'))
EOF
```
