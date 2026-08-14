# 零知识证明电路（Noir）

本目录使用 [Noir](https://noir-lang.org/) 实现凭证的**选择性披露**电路，
是 zkDID-Cred 隐私保护能力的核心。

## 设计

### 声明编码

凭证中的声明（claims）被统一编码为一个固定长度的 `Field` 向量（共 10 项），
布局见 `src/claims.nr`：

| 下标 | 含义 | 说明 |
|------|------|------|
| 0 | `gpa_scaled` | GPA×100 的整数（如 3.85 → 385）；0 表示无该声明 |
| 1 | `degree` | 学位编码（0=无, 1=学士, 2=硕士, 3=博士） |
| 2..9 | `courses` | 最多 8 门课程编码，不足补 0 |

### Poseidon2 承诺

电路对上面的声明向量计算 **Poseidon2 海绵哈希**，得到一个 `Field` 承诺值。
该承诺在签发时由学校写入凭证并签名；持有者生成证明时，电路内部重新计算承诺，
验证方将其与凭证中签名过的承诺比对，从而把证明绑定到真实的凭证声明上
（防止持有者用编造的分数/课程生成证明）。

> 实现已通过标准库自带的测试向量校验（见 `claims.nr` 中的
> `test_poseidon2_vector`），确认与 `std::hash::poseidon2` 完全一致。

### 电路入口与模式

单一入口 `main`，通过公开参数 `mode` 选择披露策略：

| mode | 策略 | 公开输入 | 私有输入 | 证明结论 |
|------|------|----------|----------|----------|
| 1 | GPA 证明 | `threshold` | `gpa_scaled` | GPA > 阈值，不泄露具体分数 |
| 2 | 课程证明 | `target_course` | `courses` | 修过目标课程，不泄露其他课程 |
| 3 | 学位证明 | `degree_code` | `degree` | 持有目标学位，不泄露成绩详情 |

## 文件结构

```
circuits/
├── Nargo.toml        # Noir 包配置
├── Prover.toml       # 示例见证输入（GPA 证明：3.85 > 3.50）
└── src/
    ├── claims.nr     # 声明编码 + Poseidon2 承诺
    └── main.nr       # 电路入口 + 测试
```

## 使用

```bash
# 编译电路（生成 ACIR）
nargo compile

# 运行测试（9 个测试：3 类策略的正确/错误输入 + 承诺校验）
nargo test

# 生成见证（使用 Prover.toml 中的示例输入）
nargo execute

# 查看电路规模（ACIR opcodes / 门数）
nargo info

# 生成/验证证明（需要安装 Barretenberg 后端 bb）
nargo execute                  # 1. 先生成见证 target/circuits.gz
bb prove -b target/circuits.json -w target/circuits.gz -o proof
bb write_vk -b target/circuits.json -o vk
bb verify -k vk -p proof       # 2. 验证证明
```

## 测试清单

| 测试 | 说明 |
|------|------|
| `test_gpa_pass` | GPA 385 > 350 通过 |
| `test_gpa_fail_below_threshold` | GPA 300 < 350 失败 |
| `test_course_pass` | 目标课程在列表中通过 |
| `test_course_fail_not_taken` | 目标课程不在列表中失败 |
| `test_degree_pass` | 学位匹配通过 |
| `test_degree_fail_wrong_degree` | 学位不匹配失败 |
| `test_commitment_binding` | 承诺与声明不符失败（防伪造） |
| `test_invalid_mode` | 非法 mode 失败 |
| `claims::test_poseidon2_vector` | Poseidon2 与标准库一致 |
