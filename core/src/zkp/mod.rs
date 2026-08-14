//! 零知识证明集成模块
//!
//! 连接 Rust 核心库与 Noir 电路：
//! - Claims：凭证声明的规范编码（与电路布局一致）
//! - commitment：Poseidon2 承诺计算（Rust 实现，与 Noir 电路一致）
//! - prove / verify：通过 shell out 到 nargo 与 bb（Barretenberg）完成证明生成与验证
//!
//! ## 环境依赖
//!
//! 证明生成与验证需要本机安装 nargo（Noir）与 bb（Barretenberg）。
//! 可用环境变量覆盖路径：NARGO、BB、ZKDID_CIRCUITS_DIR。

pub mod poseidon2;

use std::path::PathBuf;
use std::process::Command;

use crate::error::{CoreError, Result};
pub use poseidon2::Fr;

/// 最多课程数（与 circuits/src/claims.nr 一致）
pub const MAX_COURSES: usize = 8;
/// 声明向量长度（gpa + degree + courses）
pub const CLAIMS_LEN: usize = MAX_COURSES + 2;

/// 凭证声明（与 Noir 电路中的声明编码一致）
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// GPA×100 的整数（如 3.85 → 385）；0 表示无该声明
    pub gpa_scaled: u64,
    /// 学位编码（0=无, 1=学士, 2=硕士, 3=博士）
    pub degree: u64,
    /// 最多 8 门课程编码，不足补 0
    pub courses: [u64; MAX_COURSES],
}

impl Claims {
    pub fn new(gpa_scaled: u64, degree: u64, courses: [u64; MAX_COURSES]) -> Self {
        Self {
            gpa_scaled,
            degree,
            courses,
        }
    }

    /// 编码为 Field 向量（布局与 claims.nr 一致）
    pub fn encode_fields(&self) -> [Fr; CLAIMS_LEN] {
        let mut fields: [Fr; CLAIMS_LEN] = std::array::from_fn(|_| Fr::zero());
        fields[0] = Fr::from_u64(self.gpa_scaled);
        fields[1] = Fr::from_u64(self.degree);
        for i in 0..MAX_COURSES {
            fields[i + 2] = Fr::from_u64(self.courses[i]);
        }
        fields
    }
}

/// 披露策略（对应电路的 mode）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofMode {
    Gpa = 1,
    Course = 2,
    Degree = 3,
}

impl ProofMode {
    fn as_u64(self) -> u64 {
        self as u64
    }
}

/// 计算声明的 Poseidon2 承诺（与 Noir 电路一致）
pub fn commitment(claims: &Claims) -> Fr {
    poseidon2::poseidon2_hash(&claims.encode_fields())
}

/// 计算承诺并返回 0x 前缀的十六进制字符串
pub fn commitment_hex(claims: &Claims) -> String {
    commitment(claims).to_hex()
}

/// 证明产物（包含证明与公输入的路径，以及承诺值）
#[derive(Clone, Debug)]
pub struct ProofArtifact {
    pub commitment: Fr,
    pub mode: u64,
    pub threshold: u64,
    pub target_course: u64,
    pub degree_code: u64,
    pub proof_path: PathBuf,
    pub public_inputs_path: PathBuf,
}

impl ProofArtifact {
    pub fn commitment_hex(&self) -> String {
        self.commitment.to_hex()
    }
}

// ---------------------------------------------------------------------------
// 后端命令封装
// ---------------------------------------------------------------------------

fn circuits_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ZKDID_CIRCUITS_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circuits")
}

fn bin_name(env_name: &str, default: &str) -> String {
    std::env::var(env_name).unwrap_or_else(|_| default.to_string())
}

/// 在 circuits 目录下运行命令，失败时附带 stderr
fn run_in_circuits(program: &str, args: &[&str]) -> Result<String> {
    let dir = circuits_dir();
    let output = Command::new(program)
        .args(args)
        .current_dir(&dir)
        .output()
        .map_err(|e| CoreError::ZkpError(format!("failed to run {program}: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::ZkpError(format!(
            "{program} {} failed: {stderr}",
            args.join(" ")
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// 序列化 Prover.toml（Noir 见证输入）
fn write_prover_toml(
    mode: u64,
    commitment: &Fr,
    threshold: u64,
    target_course: u64,
    degree_code: u64,
    claims: &Claims,
) -> Result<()> {
    let courses_list = claims
        .courses
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let content = format!(
        "mode = \"{mode}\"\ncommitment = \"{commitment}\"\nthreshold = \"{threshold}\"\ntarget_course = \"{target_course}\"\ndegree_code = \"{degree_code}\"\ngpa_scaled = \"{gpa}\"\ndegree = \"{degree}\"\ncourses = [{courses_list}]\n",
        commitment = commitment.to_hex(),
        gpa = claims.gpa_scaled,
        degree = claims.degree,
    );

    let path = circuits_dir().join("Prover.toml");
    std::fs::write(&path, content)
        .map_err(|e| CoreError::ZkpError(format!("failed to write Prover.toml: {e}")))?;
    Ok(())
}

/// 生成证明：写见证输入 → nargo execute → bb write_vk → bb prove
pub fn prove(
    mode: ProofMode,
    threshold: u64,
    target_course: u64,
    degree_code: u64,
    claims: &Claims,
) -> Result<ProofArtifact> {
    let mode_u64 = mode.as_u64();
    let commitment = commitment(claims);

    write_prover_toml(
        mode_u64,
        &commitment,
        threshold,
        target_course,
        degree_code,
        claims,
    )?;

    let nargo = bin_name("NARGO", "nargo");
    run_in_circuits(&nargo, &["execute"])?;

    let bb = bin_name("BB", "bb");
    run_in_circuits(
        &bb,
        &["write_vk", "-b", "target/circuits.json", "-o", "target/vk"],
    )?;
    run_in_circuits(
        &bb,
        &[
            "prove",
            "-b",
            "target/circuits.json",
            "-w",
            "target/circuits.gz",
            "-o",
            "target/proof",
            "-k",
            "target/vk/vk",
        ],
    )?;

    Ok(ProofArtifact {
        commitment,
        mode: mode_u64,
        threshold,
        target_course,
        degree_code,
        proof_path: circuits_dir().join("target/proof/proof"),
        public_inputs_path: circuits_dir().join("target/proof/public_inputs"),
    })
}

/// 便捷方法：GPA 证明（GPA > threshold）
pub fn prove_gpa(claims: &Claims, threshold: u64) -> Result<ProofArtifact> {
    prove(ProofMode::Gpa, threshold, 0, 0, claims)
}

/// 便捷方法：课程证明（修过 target_course）
pub fn prove_course(claims: &Claims, target_course: u64) -> Result<ProofArtifact> {
    prove(ProofMode::Course, 0, target_course, 0, claims)
}

/// 便捷方法：学位证明（持有 degree_code 学位）
pub fn prove_degree(claims: &Claims, degree_code: u64) -> Result<ProofArtifact> {
    prove(ProofMode::Degree, 0, 0, degree_code, claims)
}

/// 验证证明（调用 bb verify），并可选地校验承诺绑定
pub fn verify(artifact: &ProofArtifact, expected_commitment: Option<&Fr>) -> Result<()> {
    if let Some(expected) = expected_commitment {
        if &artifact.commitment != expected {
            return Err(CoreError::ZkpError(
                "commitment mismatch: proof is not bound to the expected credential".to_string(),
            ));
        }
    }

    let bb = bin_name("BB", "bb");
    let vk = circuits_dir().join("target/vk/vk");
    let proof = &artifact.proof_path;
    let public_inputs = &artifact.public_inputs_path;

    run_in_circuits(
        &bb,
        &[
            "verify",
            "-k",
            vk.to_str()
                .ok_or_else(|| CoreError::ZkpError("invalid vk path".to_string()))?,
            "-p",
            proof
                .to_str()
                .ok_or_else(|| CoreError::ZkpError("invalid proof path".to_string()))?,
            "-i",
            public_inputs
                .to_str()
                .ok_or_else(|| CoreError::ZkpError("invalid public inputs path".to_string()))?,
        ],
    )?;

    Ok(())
}

/// 判断 bb / nargo 是否可用（用于跳过集成测试）
pub fn backend_available() -> bool {
    let nargo = bin_name("NARGO", "nargo");
    let bb = bin_name("BB", "bb");
    Command::new(&nargo)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && Command::new(&bb)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_claims_encoding() {
        let claims = Claims::new(385, 2, [101, 205, 0, 0, 0, 0, 0, 0]);
        let fields = claims.encode_fields();
        assert_eq!(fields.len(), CLAIMS_LEN);
        assert_eq!(fields[0], Fr::from_u64(385));
        assert_eq!(fields[1], Fr::from_u64(2));
        assert_eq!(fields[2], Fr::from_u64(101));
        assert_eq!(fields[3], Fr::from_u64(205));
        assert_eq!(fields[9], Fr::zero());
    }

    #[test]
    fn test_commitment_matches_noir() {
        // 该值由 nargo execute 对相同声明计算得出，验证 Rust 与 Noir 一致
        let claims = Claims::new(385, 0, [0; MAX_COURSES]);
        assert_eq!(
            commitment_hex(&claims),
            "0x2dec1fe4ad53fed2ef43c460bb9e997619f07f8b8a62dd8156b45921aeeb8515"
        );
    }

    #[test]
    fn test_commitment_differs_per_claims() {
        let a = Claims::new(385, 0, [0; MAX_COURSES]);
        let b = Claims::new(300, 0, [0; MAX_COURSES]);
        assert_ne!(commitment(&a), commitment(&b));
    }
}
