use anyhow::Result;
use chrono::Utc;
use clap::{Parser, Subcommand};
use core::crypto::KeyPair;
use core::did::Did;
use core::vc::{CredentialSubject, VerifiableCredential};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "issuer-cli")]
#[command(about = "Issuer CLI for signing and issuing Verifiable Credentials", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize issuer identity (generate DID)
    Init {
        /// Issuer name (e.g., "Beijing University")
        #[arg(short, long)]
        name: String,
    },
    /// Issue a new credential to a holder
    Issue {
        /// Holder's DID
        #[arg(long)]
        holder: String,
        /// Credential type (e.g., "UniversityDegreeCredential")
        #[arg(long)]
        credential_type: String,
        /// Claims as JSON string (e.g., '{"degree":"Computer Science","gpa":3.8}')
        #[arg(long)]
        claims: String,
        /// Expiration date (RFC3339 format, optional)
        #[arg(long)]
        expiration: Option<String>,
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct IssuerIdentity {
    name: String,
    did: String,
    secret_key: String,
}

fn get_issuer_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
    let issuer_dir = home.join(".zkdid-issuer");
    if !issuer_dir.exists() {
        fs::create_dir_all(&issuer_dir)?;
    }
    Ok(issuer_dir)
}

fn load_issuer_identity() -> Result<IssuerIdentity> {
    let issuer_dir = get_issuer_dir()?;
    let identity_path = issuer_dir.join("identity.json");

    if !identity_path.exists() {
        anyhow::bail!("Issuer identity not found. Please run 'issuer-cli init' first.");
    }

    let content = fs::read_to_string(&identity_path)?;
    let identity: IssuerIdentity = serde_json::from_str(&content)?;
    Ok(identity)
}

fn cmd_init(name: String) -> Result<()> {
    let issuer_dir = get_issuer_dir()?;
    let identity_path = issuer_dir.join("identity.json");

    if identity_path.exists() {
        println!(
            "⚠️  Issuer identity already exists at: {}",
            identity_path.display()
        );
        let content = fs::read_to_string(&identity_path)?;
        let identity: IssuerIdentity = serde_json::from_str(&content)?;
        println!("🏛️  Issuer: {}", identity.name);
        println!("📇 DID: {}", identity.did);
        return Ok(());
    }

    println!("🔑 Generating new issuer identity...");
    let keypair = KeyPair::generate();
    let did = Did::from_public_key(&keypair.public);

    let identity = IssuerIdentity {
        name: name.clone(),
        did: did.to_string(),
        secret_key: keypair.secret_to_base58(),
    };

    fs::write(&identity_path, serde_json::to_string_pretty(&identity)?)?;

    println!("✅ Issuer identity created!");
    println!("🏛️  Issuer: {}", name);
    println!("📇 DID: {}", identity.did);
    println!("💾 Saved to: {}", identity_path.display());
    Ok(())
}

fn cmd_issue(
    holder: String,
    credential_type: String,
    claims: String,
    expiration: Option<String>,
    output: PathBuf,
) -> Result<()> {
    // Load issuer identity
    let issuer_identity = load_issuer_identity()?;
    println!("🏛️  Issuer: {}", issuer_identity.name);
    println!("📇 Issuer DID: {}", issuer_identity.did);

    // Reconstruct keypair from secret key
    let keypair = KeyPair::from_base58_secret(&issuer_identity.secret_key)?;

    // Parse claims JSON
    let claims_value: serde_json::Value =
        serde_json::from_str(&claims).map_err(|e| anyhow::anyhow!("Invalid claims JSON: {}", e))?;

    // Create credential
    let credential_id = format!("urn:uuid:{}", Uuid::new_v4());
    let credential = VerifiableCredential {
        context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
        id: credential_id.clone(),
        types: vec!["VerifiableCredential".to_string(), credential_type.clone()],
        issuer: issuer_identity.did.clone(),
        issuance_date: Utc::now().to_rfc3339(),
        expiration_date: expiration,
        credential_subject: CredentialSubject {
            id: holder.clone(),
            claims: claims_value,
        },
        credential_status: None,
        proof: None,
    };

    // Sign credential
    println!("✍️  Signing credential...");
    let signed_credential = core::vc::issue_credential(credential, &keypair)?;

    // Save to file
    fs::write(&output, serde_json::to_string_pretty(&signed_credential)?)?;

    println!("✅ Credential issued successfully!");
    println!("📋 Credential ID: {}", credential_id);
    println!("👤 Holder: {}", holder);
    println!("📄 Type: {}", credential_type);
    println!("💾 Saved to: {}", output.display());
    println!("\n📤 Send this file to the holder to use 'holder-cli receive'");

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name } => cmd_init(name),
        Commands::Issue {
            holder,
            credential_type,
            claims,
            expiration,
            output,
        } => cmd_issue(holder, credential_type, claims, expiration, output),
    }
}
