//! 零知识证明端到端演示
//!
//! 完整流程：Rust 计算承诺 → nargo 生成见证 → bb 生成/验证证明。
//!
//! 运行方式（确保 nargo / bb 在 PATH 中）：
//!   PATH="$HOME/.bb:$PATH" cargo run -p core --example zkp_demo

use core::zkp::{self, Claims};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> core::Result<()> {
    if !zkp::backend_available() {
        eprintln!("nargo / bb 未安装，跳过证明生成演示。");
        eprintln!("安装方式：noirup（nargo）+ bbup（bb）");
        return Ok(());
    }

    println!("=== zkDID-Cred: 零知识证明端到端演示 ===\n");

    // 学生声明：GPA 3.85（385）、学士学位（1）、修过两门课
    let claims = Claims::new(385, 1, [101, 205, 0, 0, 0, 0, 0, 0]);

    // 1. 计算承诺（签发方会把该值写入凭证并签名）
    let commitment = zkp::commitment(&claims);
    println!("1. 声明承诺: {}", commitment.to_hex());

    // 2. GPA 证明：证明 GPA > 3.5（350），不泄露具体分数
    println!("\n2. 生成 GPA 证明（GPA > 3.5）...");
    let artifact = zkp::prove_gpa(&claims, 350)?;
    println!(
        "   ✓ 证明已生成（mode={}, threshold={}）",
        artifact.mode, artifact.threshold
    );
    zkp::verify(&artifact, Some(&commitment))?;
    println!("   ✓ 验证通过，且承诺绑定一致");

    // 3. 课程证明：证明修过课程 205，不泄露其他课程
    println!("\n3. 生成课程证明（修过课程 205）...");
    let course_artifact = zkp::prove_course(&claims, 205)?;
    zkp::verify(&course_artifact, Some(&commitment))?;
    println!("   ✓ 验证通过");

    // 4. 学位证明：证明持有学士学位（1）
    println!("\n4. 生成学位证明（持有学士学位）...");
    let degree_artifact = zkp::prove_degree(&claims, 1)?;
    zkp::verify(&degree_artifact, Some(&commitment))?;
    println!("   ✓ 验证通过");

    // 5. 防伪造演示：错误的承诺应被拒绝
    println!("\n5. 演示防伪造（错误的承诺应被拒绝）...");
    let wrong = zkp::Fr::from_u64(0xdeadbeef);
    match zkp::verify(&artifact, Some(&wrong)) {
        Ok(_) => println!("   ✗ 不应通过（bug）"),
        Err(e) => println!("   ✓ 正确拒绝: {e}"),
    }

    println!("\n=== 演示完成 ===");
    Ok(())
}
