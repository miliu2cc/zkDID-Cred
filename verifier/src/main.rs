mod api;
mod service;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use zkdid_core::vc::VerifiableCredential;

#[derive(Parser)]
#[command(name = "verifier-cli")]
#[command(about = "验证方：验证凭证（CLI + HTTP 服务）", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 验证一张凭证（CLI）
    Verify {
        #[arg(short, long)]
        credential: PathBuf,
        #[arg(short, long)]
        verbose: bool,
    },
    /// 启动 HTTP 服务
    Serve {
        #[arg(long, default_value_t = 8081)]
        port: u16,
    },
}

fn cmd_verify(credential_path: PathBuf, verbose: bool) -> Result<()> {
    let content = fs::read_to_string(&credential_path)?;
    let credential: VerifiableCredential = serde_json::from_str(&content)?;

    let report = service::verify(&credential);

    println!("📋 Credential ID: {}", report.credential_id);
    println!("🏛️  Issuer: {}", report.issuer);
    println!("👤 Subject: {}", report.subject);

    if report.valid {
        println!("✅ {}", report.message);
        println!("✅ VERIFICATION SUCCESSFUL");
        if verbose {
            println!(
                "
📊 Details:"
            );
            println!("{}", serde_json::to_string_pretty(&credential)?);
        }
        Ok(())
    } else {
        println!("❌ {}", report.message);
        println!("❌ VERIFICATION FAILED");
        std::process::exit(1);
    }
}

async fn serve(port: u16) -> Result<()> {
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("🚀 Verifier 服务已启动: http://{addr}");
    println!("   端点: POST /verify, GET /health");
    axum::serve(listener, api::router()).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify {
            credential,
            verbose,
        } => cmd_verify(credential, verbose),
        Commands::Serve { port } => serve(port).await,
    }
}
