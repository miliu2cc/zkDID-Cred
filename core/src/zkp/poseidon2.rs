//! Barretenberg Poseidon2（BN254 标量域）
//!
//! 与 Noir `std::hash::poseidon2` 完全一致的实现，用于在 Rust 侧
//! （签发方 / 验证方）计算凭证声明的 Poseidon2 承诺，
//! 保证与 Noir 电路内部的承诺计算一致。

use std::sync::OnceLock;

use num_bigint::BigUint;

#[path = "poseidon2_constants.rs"]
mod poseidon2_constants;

use poseidon2_constants::{MDS_DIAG_MINUS_ONE, ROUND_CONSTANTS};

/// BN254 标量域模数 p（十六进制）
const MODULUS_HEX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

/// 域元素（运算时自动约化到 [0, p)）
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fr(BigUint);

impl Fr {
    fn modulus() -> &'static BigUint {
        static P: OnceLock<BigUint> = OnceLock::new();
        P.get_or_init(|| BigUint::parse_bytes(MODULUS_HEX.as_bytes(), 16).expect("valid modulus"))
    }

    pub fn zero() -> Self {
        Fr(BigUint::from(0u64))
    }

    pub fn from_u64(v: u64) -> Self {
        Fr(BigUint::from(v))
    }

    /// 从十六进制字符串（可带 0x 前缀）解析并约化
    pub fn from_hex(s: &str) -> Self {
        let h = s.strip_prefix("0x").unwrap_or(s);
        let v = BigUint::parse_bytes(h.as_bytes(), 16).expect("valid hex");
        Fr(v % Fr::modulus())
    }

    fn from_biguint_reduced(v: BigUint) -> Self {
        Fr(v % Fr::modulus())
    }

    pub fn add(&self, other: &Fr) -> Fr {
        Fr((&self.0 + &other.0) % Fr::modulus())
    }

    pub fn mul(&self, other: &Fr) -> Fr {
        Fr((&self.0 * &other.0) % Fr::modulus())
    }

    /// x^5
    pub fn pow5(&self) -> Fr {
        let x2 = self.mul(self);
        let x4 = x2.mul(&x2);
        x4.mul(self)
    }

    /// 输出 0x 前缀、64 位十六进制的小写字符串
    pub fn to_hex(&self) -> String {
        let raw = format!("{:x}", self.0);
        format!("0x{:0>64}", raw)
    }
}

fn round_constants() -> &'static [[Fr; 4]; 64] {
    static RC: OnceLock<[[Fr; 4]; 64]> = OnceLock::new();
    RC.get_or_init(|| {
        let mut arr: [[Fr; 4]; 64] = std::array::from_fn(|_| std::array::from_fn(|_| Fr::zero()));
        for i in 0..64 {
            for j in 0..4 {
                arr[i][j] = Fr::from_hex(ROUND_CONSTANTS[i][j]);
            }
        }
        arr
    })
}

fn mds_diag_minus_one() -> &'static [Fr; 4] {
    static D: OnceLock<[Fr; 4]> = OnceLock::new();
    D.get_or_init(|| {
        let mut a: [Fr; 4] = std::array::from_fn(|_| Fr::zero());
        for i in 0..4 {
            a[i] = Fr::from_hex(MDS_DIAG_MINUS_ONE[i]);
        }
        a
    })
}

/// 外部 MDS 矩阵乘法（4×4，来自 Poseidon2 论文的硬编码优化）
///
/// MDS 矩阵为 [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]。
fn matrix_mul_external(state: &mut [Fr; 4]) {
    let a = state[0].clone();
    let b = state[1].clone();
    let c = state[2].clone();
    let d = state[3].clone();

    let t0 = a.add(&b); // A + B
    let t1 = c.add(&d); // C + D
    let mut t2 = b.add(&b); // 2B
    t2 = t2.add(&t1); // 2B + C + D
    let mut t3 = d.add(&d); // 2D
    t3 = t3.add(&t0); // 2D + A + B
    let mut t4 = t1.add(&t1); // 2(C+D)
    t4 = t4.add(&t4); // 4(C+D)
    t4 = t4.add(&t3); // A + B + 4C + 6D
    let mut t5 = t0.add(&t0); // 2(A+B)
    t5 = t5.add(&t5); // 4(A+B)
    t5 = t5.add(&t2); // 4A + 6B + C + D
    let t6 = t3.add(&t5); // 5A + 7B + C + 3D
    let t7 = t2.add(&t4); // A + 3B + 5C + 7D

    state[0] = t6;
    state[1] = t5;
    state[2] = t7;
    state[3] = t4;
}

/// 内部 MDS 矩阵乘法：result[i] = (D_i - 1) * input[i] + sum
fn matrix_mul_internal(state: &mut [Fr; 4]) {
    let sum = state[0].add(&state[1]).add(&state[2]).add(&state[3]);
    let diag = mds_diag_minus_one();
    for i in 0..4 {
        state[i] = state[i].mul(&diag[i]).add(&sum);
    }
}

fn apply_sbox_all(state: &mut [Fr; 4]) {
    for i in 0..4 {
        state[i] = state[i].pow5();
    }
}

fn add_round_constants(state: &mut [Fr; 4], round: usize) {
    let rc = round_constants();
    for i in 0..4 {
        state[i] = state[i].add(&rc[round][i]);
    }
}

/// Poseidon2 排列（t=4）：初始线性层 + 4 完整轮 + 56 部分轮 + 4 完整轮
pub fn permutation(input: &[Fr; 4]) -> [Fr; 4] {
    let mut state = input.clone();

    // 初始线性层
    matrix_mul_external(&mut state);

    // 前 4 个完整轮（S-box 作用于全部元素）
    for i in 0..4 {
        add_round_constants(&mut state, i);
        apply_sbox_all(&mut state);
        matrix_mul_external(&mut state);
    }

    // 56 个部分轮（S-box 仅作用于第 0 个元素）
    for i in 4..60 {
        state[0] = state[0].add(&round_constants()[i][0]);
        state[0] = state[0].pow5();
        matrix_mul_internal(&mut state);
    }

    // 后 4 个完整轮
    for i in 60..64 {
        add_round_constants(&mut state, i);
        apply_sbox_all(&mut state);
        matrix_mul_external(&mut state);
    }

    state
}

/// Poseidon2 海绵哈希（容量 1、速率 3），与 Noir std::hash::poseidon2 一致
pub fn poseidon2_hash(input: &[Fr]) -> Fr {
    const RATE: usize = 3;
    let n = input.len();

    let mut state = [Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero()];
    // 初始向量 iv = (输入长度 << 64)
    let iv = Fr::from_biguint_reduced(BigUint::from(n as u64) << 64usize);
    state[RATE] = iv;

    let mut i = 0;
    while i + RATE <= n {
        for j in 0..RATE {
            state[j] = state[j].add(&input[i + j]);
        }
        state = permutation(&state);
        i += RATE;
    }

    let absorbed = i;
    for j in 0..(n - absorbed) {
        state[j] = state[j].add(&input[absorbed + j]);
    }

    permutation(&state)[0].clone()
}

#[cfg(test)]
mod tests {
    use super::poseidon2_constants::PERMUTATION_TEST_OUTPUT;
    use super::*;

    #[test]
    fn test_permutation_vector() {
        // 与 Barretenberg poseidon2_params.hpp 的 TEST_VECTOR 一致
        let input = [
            Fr::from_u64(0),
            Fr::from_u64(1),
            Fr::from_u64(2),
            Fr::from_u64(3),
        ];
        let out = permutation(&input);
        for i in 0..4 {
            assert_eq!(out[i].to_hex(), PERMUTATION_TEST_OUTPUT[i].to_lowercase());
        }
    }

    #[test]
    fn test_sponge_hash_vector() {
        // 与 Noir std::hash::poseidon2 的测试向量一致
        let input = [
            Fr::from_u64(1),
            Fr::from_u64(2),
            Fr::from_u64(3),
            Fr::from_u64(4),
            Fr::from_u64(5),
        ];
        let h = poseidon2_hash(&input);
        assert_eq!(
            h.to_hex(),
            "0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db"
        );
    }

    #[test]
    fn test_field_arithmetic() {
        let five = Fr::from_u64(5);
        assert_eq!(five.pow5(), Fr::from_u64(3125)); // 5^5 = 3125

        // 模数 p 本身约化为 0
        let p = Fr::from_hex(MODULUS_HEX);
        assert_eq!(p, Fr::zero());

        // p - 1 + 1 ≡ 0 (mod p)
        let p_minus_1 =
            Fr::from_hex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
        assert_eq!(p_minus_1.add(&Fr::from_u64(1)), Fr::zero());
    }
}
