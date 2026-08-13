use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use core::vc::VerifiableCredential;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "verifier-cli")]
#[command(about = "Verifier CLI for validating Verifiable Credentials", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a credential's signature and validity
    Verify {
        /// Path to the credential JSON file
        #[arg(short, long)]
        credential: PathBuf,
        /// Show detailed credential information
        #[arg(short, long)]
        verbose: bool,
    },
}

fn cmd_verify(credential_path: PathBuf, verbose: bool) -> Result<()> {
    println!("🔍 Loading credential from: {}", credential_path.display());

    // Read credential file
    let content = fs::read_to_string(&credential_path)?;
    let credential: VerifiableCredential = serde_json::from_str(&content)?;

    println!("📋 Credential ID: {}", credential.id);
    println!("📄 Type: {:?}", credential.types);
    println!("🏛️  Issuer: {}", credential.issuer);
    println!("📅 Issued: {}", credential.issuance_date);

    // Check expiration
    if let Some(exp) = &credential.expiration_date {
        println!("⏰ Expires: {}", exp);
        let expiration: DateTime<Utc> = exp.parse()?;
        if expiration < Utc::now() {
            println!("\n❌ EXPIRED: This credential has expired!");
            anyhow::bail!("Credential expired on {}", exp);
        }
    } else {
        println!("⏰ Expires: Never");
    }

    // Verify signature
    println!("\n🔐 Verifying signature...");
    match core::vc::verify_credential(&credential) {
        Ok(_) => {
            println!("✅ Signature valid!");
            println!("✅ Credential is authentic and has not been tampered with.");

            if verbose {
                println!("\n📊 Credential Details:");
                println!("👤 Subject ID: {}", credential.credential_subject.id);
                println!("📝 Claims:");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&credential.credential_subject.claims)?
                );

                if let Some(proof) = &credential.proof {
                    println!("\n🔏 Proof Details:");
                    println!("  Type: {}", proof.type_);
                    println!("  Created: {}", proof.created);
                    println!("  Verification Method: {}", proof.verification_method);
                    println!("  Purpose: {}", proof.proof_purpose);
                }
            }

            println!("\n✅ VERIFICATION SUCCESSFUL");
            Ok(())
        }
        Err(e) => {
            println!("❌ Signature verification failed!");
            println!("❌ Error: {}", e);
            println!("\n⚠️  This credential may have been tampered with or is invalid.");
            Err(e.into())
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Verify {
            credential,
            verbose,
        } => cmd_verify(credential, verbose),
    };

    // Verification failure is an expected business outcome, not a crash.
    // Exit with a non-zero code but without printing a Rust backtrace.
    if result.is_err() {
        std::process::exit(1);
    }
}
