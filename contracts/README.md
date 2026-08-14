# 智能合约（Foundry）

本目录使用 [Foundry](https://book.getfoundry.sh/) 开发以太坊智能合约，
为 zkDID-Cred 提供链上可信基础设施（可选集成）。

## 合约

| 合约 | 用途 |
|------|------|
| `DIDRegistry.sol` | DID 注册与解析，支持转移控制权与注销 |
| `IssuerRegistry.sol` | 学校（签发方）白名单管理 |
| `VCRegistry.sol` | 凭证哈希上链（防篡改时间戳）与撤销列表管理 |

## 使用

```bash
# 编译
forge build

# 测试（19 个测试）
forge test -vv

# 启动本地节点（可选）
anvil
```

## 测试清单

- `DIDRegistry.t.sol`（8 个）：注册、解析、重复注册失败、空 DID 失败、转移控制权、越权转移失败、注销、解析未知 DID 失败
- `IssuerRegistry.t.sol`（6 个）：构造函数、添加/移除签发方、非 owner 操作失败、重复添加失败、授权查询
- `VCRegistry.t.sol`（5 个）：注册凭证、重复注册失败、撤销、越权撤销失败、撤销未知凭证失败
