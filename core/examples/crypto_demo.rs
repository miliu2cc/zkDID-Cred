//! Cryptographic operations demonstration
//!
//! Run with: cargo run --example crypto_demo

use core::crypto::KeyPair;

fn main() {
    println!("=== zkDID-Cred 密码学模块演示 ===\n");

    // 1. 生成密钥对
    println!("1. 生成新的 Ed25519 密钥对...");
    let keypair = KeyPair::generate();
    println!("   ✓ 密钥对生成成功");

    // 2. 查看公钥
    println!("\n2. 公钥信息:");
    println!("   Base58: {}", keypair.public.to_base58());
    println!("   Hex:    {}", keypair.public.to_hex());
    println!("   字节长度: {} bytes", keypair.public.to_bytes().len());

    // 3. 签名消息
    println!("\n3. 签名消息...");
    let message = b"Hello, zkDID-Cred!";
    println!("   原始消息: {}", String::from_utf8_lossy(message));
    let signature = keypair.sign(message);
    println!("   ✓ 签名生成成功");
    println!("   签名长度: {} bytes", signature.len());
    println!("   签名 (hex): {}", hex::encode(&signature[..16]) + "...");

    // 4. 验证签名
    println!("\n4. 验证签名...");
    match keypair.public.verify(message, &signature) {
        Ok(_) => println!("   ✓ 签名验证成功！"),
        Err(e) => println!("   ✗ 签名验证失败: {}", e),
    }

    // 5. 验证错误消息（应该失败）
    println!("\n5. 验证错误消息（预期失败）...");
    let wrong_message = b"Wrong message";
    match keypair.public.verify(wrong_message, &signature) {
        Ok(_) => println!("   ✗ 不应该验证成功！"),
        Err(_) => println!("   ✓ 正确拒绝了错误消息"),
    }

    // 6. 密钥序列化与恢复
    println!("\n6. 密钥序列化与恢复...");
    let secret_base58 = keypair.secret_to_base58();
    println!("   密钥已编码为 Base58");

    let restored_keypair = KeyPair::from_base58_secret(&secret_base58).unwrap();
    println!("   ✓ 密钥恢复成功");

    // 验证恢复的密钥是否相同
    if keypair.public.to_bytes() == restored_keypair.public.to_bytes() {
        println!("   ✓ 公钥匹配");
    }

    // 7. 使用恢复的密钥签名
    println!("\n7. 使用恢复的密钥签名...");
    let new_signature = restored_keypair.sign(message);
    match keypair.public.verify(message, &new_signature) {
        Ok(_) => println!("   ✓ 恢复的密钥可以正常签名和验证"),
        Err(_) => println!("   ✗ 验证失败"),
    }

    // 8. 多个密钥对演示
    println!("\n8. 生成第二个密钥对并交叉验证...");
    let keypair2 = KeyPair::generate();
    let signature2 = keypair2.sign(message);

    // 用错误的公钥验证（应该失败）
    match keypair.public.verify(message, &signature2) {
        Ok(_) => println!("   ✗ 不应该验证成功！"),
        Err(_) => println!("   ✓ 正确拒绝了其他密钥的签名"),
    }

    println!("\n=== 演示完成 ===");
}
