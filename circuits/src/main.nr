//! zkDID-Cred 选择性披露电路
//!
//! 单一电路入口，通过公开参数 mode 选择要证明的披露策略：
//!   mode 1 — GPA 证明：证明 GPA > 阈值，不泄露具体分数
//!   mode 2 — 课程证明：证明修过某门课，不泄露其他课程
//!   mode 3 — 学位证明：证明持有某学位，不泄露成绩详情
//!
//! 所有模式都会校验：私有声明的 Poseidon2 承诺 == 公开的 commitment，
//! 从而把证明绑定到由签发方（学校）签名的凭证声明上。

mod claims;

use claims::{CLAIMS_LEN, MAX_COURSES, poseidon2_hash};

/// 判断课程列表是否包含目标课程
fn contains(target: u64, courses: [u64; MAX_COURSES]) -> bool {
    let mut found = false;
    for i in 0..MAX_COURSES {
        found = found | (courses[i] == target);
    }
    found
}

/// 将私有声明编码为 Field 向量（布局见 claims.nr）
fn encode_claims(gpa_scaled: u64, degree: u64, courses: [u64; MAX_COURSES]) -> [Field; CLAIMS_LEN] {
    let mut fields = [0; CLAIMS_LEN];
    fields[0] = gpa_scaled as Field;
    fields[1] = degree as Field;
    for i in 0..MAX_COURSES {
        fields[i + 2] = courses[i] as Field;
    }
    fields
}

fn main(
    // —— 公开输入（披露策略 + 承诺）——
    mode: pub u64,
    commitment: pub Field,
    threshold: pub u64,
    target_course: pub u64,
    degree_code: pub u64,
    // —— 私有输入（学生真实声明）——
    gpa_scaled: u64,
    degree: u64,
    courses: [u64; MAX_COURSES],
) {
    // 1) 声明必须与公开的承诺一致（把证明绑定到签发方签名的凭证）
    let fields = encode_claims(gpa_scaled, degree, courses);
    assert(commitment == poseidon2_hash(fields));

    // 2) 按模式执行对应的披露策略
    let is_gpa = mode == 1;
    let is_course = mode == 2;
    let is_degree = mode == 3;
    assert((mode == 1) | (mode == 2) | (mode == 3));

    assert((!is_gpa) | (gpa_scaled > threshold));
    assert((!is_course) | contains(target_course, courses));
    assert((!is_degree) | (degree == degree_code));
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[test]
fn test_gpa_pass() {
    let gpa = 385; // 3.85
    let courses = [0; MAX_COURSES];
    let commitment = poseidon2_hash(encode_claims(gpa, 0, courses));
    main(1, commitment, 350, 0, 0, gpa, 0, courses);
}

#[test(should_fail)]
fn test_gpa_fail_below_threshold() {
    let gpa = 300; // 3.00 < 3.50
    let courses = [0; MAX_COURSES];
    let commitment = poseidon2_hash(encode_claims(gpa, 0, courses));
    main(1, commitment, 350, 0, 0, gpa, 0, courses);
}

#[test]
fn test_course_pass() {
    let courses = [101, 205, 0, 0, 0, 0, 0, 0];
    let commitment = poseidon2_hash(encode_claims(0, 0, courses));
    main(2, commitment, 0, 205, 0, 0, 0, courses);
}

#[test(should_fail)]
fn test_course_fail_not_taken() {
    let courses = [101, 205, 0, 0, 0, 0, 0, 0];
    let commitment = poseidon2_hash(encode_claims(0, 0, courses));
    main(2, commitment, 0, 999, 0, 0, 0, courses);
}

#[test]
fn test_degree_pass() {
    let courses = [0; MAX_COURSES];
    let commitment = poseidon2_hash(encode_claims(0, 2, courses));
    main(3, commitment, 0, 0, 2, 0, 2, courses);
}

#[test(should_fail)]
fn test_degree_fail_wrong_degree() {
    let courses = [0; MAX_COURSES];
    let commitment = poseidon2_hash(encode_claims(0, 1, courses));
    main(3, commitment, 0, 0, 2, 0, 1, courses);
}

#[test(should_fail)]
fn test_commitment_binding() {
    // 声明与承诺不匹配时必须失败（防伪造：不能拿别人的承诺来证明自己的声明）
    let gpa = 385;
    let courses = [0; MAX_COURSES];
    let wrong_commitment = 0xdeadbeef;
    main(1, wrong_commitment, 350, 0, 0, gpa, 0, courses);
}

#[test(should_fail)]
fn test_invalid_mode() {
    let courses = [0; MAX_COURSES];
    let commitment = poseidon2_hash(encode_claims(0, 0, courses));
    main(99, commitment, 0, 0, 0, 0, 0, courses);
}
