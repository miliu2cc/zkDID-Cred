mod api;
mod service;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "issuer-cli")]
#[command(about = "学校端：签发凭证（CLI + HTTP 服务）", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 初始化签发方身份（生成 DID）
    Init {
        #[arg(short, long)]
        name: String,
    },
    /// 签发一张凭证（CLI）
    Issue {
        /// 学生 DID
        #[arg(long)]
        holder: String,
        /// 凭证类型
        #[arg(long)]
        credential_type: String,
        /// 声明 JSON，ZK 兼容 schema：{"gpa":3.85,"degree":"bachelor","courses":[101,205]}
        #[arg(long)]
        claims: String,
        /// 过期时间（RFC3339，可选）
        #[arg(long)]
        expiration: Option<String>,
        /// 输出文件路径
        #[arg(short, long)]
        output: PathBuf,
    },
    /// 启动 HTTP 服务
    Serve {
        /// 监听端口
        #[arg(long, default_value_t = 8080)]
        port: u16,
    },
}

fn cmd_init(name: &str) -> Result<()> {
    let identity = service::init_identity(name)?;
    println!("✅ Issuer identity ready!");
    println!("🏛️  Issuer: {}", identity.name);
    println!("📇 DID: {}", identity.did);
    Ok(())
}

fn cmd_issue(
    holder: &str,
    credential_type: &str,
    claims: &str,
    expiration: Option<String>,
    output: &PathBuf,
) -> Result<()> {
    let identity = service::load_identity()?;
    let claims_value: serde_json::Value =
        serde_json::from_str(claims).map_err(|e| anyhow::anyhow!("Invalid claims JSON: {e}"))?;

    let vc = service::issue(&identity, holder, credential_type, claims_value, expiration)?;
    let commitment = zkdid_core::zkp::commitment_of_credential(&vc)?;

    std::fs::write(output, serde_json::to_string_pretty(&vc)?)?;

    println!("✅ Credential issued successfully!");
    println!("📋 Credential ID: {}", vc.id);
    println!("👤 Holder: {}", holder);
    println!("📄 Type: {}", credential_type);
    println!("🔐 Claims Commitment: {}", commitment.to_hex());
    println!("💾 Saved to: {}", output.display());
    Ok(())
}

async fn serve(port: u16) -> Result<()> {
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("🚀 Issuer 服务已启动: http://{addr}");
    println!("   端点: POST /init, GET /did, POST /issue, GET /health");
    axum::serve(listener, api::router()).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name } => cmd_init(&name),
        Commands::Issue {
            holder,
            credential_type,
            claims,
            expiration,
            output,
        } => cmd_issue(&holder, &credential_type, &claims, expiration, &output),
        Commands::Serve { port } => serve(port).await,
    }
}
