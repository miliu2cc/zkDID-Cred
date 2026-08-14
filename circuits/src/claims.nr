//! 凭证声明的规范编码与 Poseidon2 承诺
//!
//! 所有证明电路共享同一套“声明 → Field 向量”的编码规则，
//! 使得不同电路可以引用同一张凭证的同一个承诺值，
//! 从而把零知识证明绑定到由签发方（学校）签名的具体声明上。
//!
//! 声明布局（共 CLAIMS_LEN = 10 个 Field）：
//!   [0]     gpa_scaled   GPA×100 的整数（如 3.85 → 385）；0 表示无该声明
//!   [1]     degree       学位编码（0=无, 1=学士, 2=硕士, 3=博士）
//!   [2..9]  courses      最多 MAX_COURSES=8 门课程编码，不足补 0

use std::hash::poseidon2_permutation;

pub global MAX_COURSES: u32 = 8;
pub global CLAIMS_LEN: u32 = MAX_COURSES + 2;

// Poseidon2 状态大小与速率（Barretenberg 后端配置：容量 1）
pub global POSEIDON2_STATE_SIZE: u32 = 4;
pub global POSEIDON2_RATE: u32 = 3;

/// 对固定长度 Field 数组做 Poseidon2 海绵哈希。
///
/// 复刻 std::hash::poseidon2 的 sponge 算法：
/// 容量 1、速率 (状态大小 - 1)，初始向量 iv = (输入长度 << 64)。
pub fn poseidon2_hash<let N: u32>(input: [Field; N]) -> Field {
    let iv: Field = (N as Field) * 18446744073709551616;
    let mut state = [0; POSEIDON2_STATE_SIZE];
    state[POSEIDON2_RATE] = iv;

    for i in 0..(N / POSEIDON2_RATE) {
        for j in 0..POSEIDON2_RATE {
            state[j] += input[i * POSEIDON2_RATE + j];
        }
        state = poseidon2_permutation(state);
    }

    let absorbed = (N / POSEIDON2_RATE) * POSEIDON2_RATE;
    for i in 0..(N % POSEIDON2_RATE) {
        state[i] += input[absorbed + i];
    }

    poseidon2_permutation(state)[0]
}

#[test]
fn test_poseidon2_vector() {
    // 与 std::hash::poseidon2 内部测试向量一致，
    // 用于校验本实现与标准库的 sponge 算法完全一致。
    let h = poseidon2_hash([1, 2, 3, 4, 5]);
    assert_eq(h, 0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db);
}
