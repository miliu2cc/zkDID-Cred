use anyhow::Result;
use clap::{Parser, Subcommand};
use core::crypto::KeyPair;
use core::did::Did;
use core::vc::VerifiableCredential;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "holder-cli")]
#[command(about = "Holder CLI for managing DIDs and Verifiable Credentials", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize holder identity (generate DID)
    Init,
    /// Receive and save a verifiable credential
    Receive {
        /// Path to the credential JSON file
        #[arg(short, long)]
        credential: PathBuf,
    },
    /// List all stored credentials
    List,
    /// Show details of a specific credential
    Show {
        /// Credential ID
        id: String,
    },
}

#[derive(Serialize, Deserialize)]
struct HolderIdentity {
    did: String,
    secret_key: String,
}

fn get_holder_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
    let holder_dir = home.join(".zkdid-holder");
    if !holder_dir.exists() {
        fs::create_dir_all(&holder_dir)?;
    }
    Ok(holder_dir)
}

fn get_credentials_dir() -> Result<PathBuf> {
    let holder_dir = get_holder_dir()?;
    let creds_dir = holder_dir.join("credentials");
    if !creds_dir.exists() {
        fs::create_dir_all(&creds_dir)?;
    }
    Ok(creds_dir)
}

fn cmd_init() -> Result<()> {
    let holder_dir = get_holder_dir()?;
    let identity_path = holder_dir.join("identity.json");

    if identity_path.exists() {
        println!(
            "⚠️  Identity already exists at: {}",
            identity_path.display()
        );
        let content = fs::read_to_string(&identity_path)?;
        let identity: HolderIdentity = serde_json::from_str(&content)?;
        println!("📇 Your DID: {}", identity.did);
        return Ok(());
    }

    println!("🔑 Generating new holder identity...");
    let keypair = KeyPair::generate();
    let did = Did::from_public_key(&keypair.public);

    let identity = HolderIdentity {
        did: did.to_string(),
        secret_key: keypair.secret_to_base58(),
    };

    fs::write(&identity_path, serde_json::to_string_pretty(&identity)?)?;

    println!("✅ Identity created!");
    println!("📇 Your DID: {}", identity.did);
    println!("💾 Saved to: {}", identity_path.display());
    Ok(())
}

fn cmd_receive(credential_path: PathBuf) -> Result<()> {
    // Read credential file
    let content = fs::read_to_string(&credential_path)?;
    let credential: VerifiableCredential = serde_json::from_str(&content)?;

    // Verify credential first
    println!("🔍 Verifying credential...");
    core::vc::verify_credential(&credential)?;
    println!("✅ Credential verified!");

    // Save to credentials directory
    let creds_dir = get_credentials_dir()?;
    let cred_id = credential
        .id
        .split(':')
        .last()
        .unwrap_or("unknown")
        .to_string();
    let dest_path = creds_dir.join(format!("{}.json", cred_id));

    fs::write(&dest_path, serde_json::to_string_pretty(&credential)?)?;

    println!("💾 Credential saved: {}", dest_path.display());
    println!("📋 Credential ID: {}", credential.id);
    println!("📄 Type: {:?}", credential.types);
    Ok(())
}

fn cmd_list() -> Result<()> {
    let creds_dir = get_credentials_dir()?;
    let entries = fs::read_dir(&creds_dir)?;

    let mut count = 0;
    println!("📚 Stored Credentials:\n");

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let content = fs::read_to_string(&path)?;
            let credential: VerifiableCredential = serde_json::from_str(&content)?;

            let short_id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");

            count += 1;
            println!("{}. {}", count, credential.id);
            println!("   Type: {:?}", credential.types);
            println!("   Issuer: {}", credential.issuer);
            println!("   Issued: {}", credential.issuance_date);
            println!("   → show with: holder-cli show {}", short_id);
            println!();
        }
    }

    if count == 0 {
        println!("No credentials found. Use 'receive' to add credentials.");
    }

    Ok(())
}

fn cmd_show(id: String) -> Result<()> {
    let creds_dir = get_credentials_dir()?;

    // Accept both the full id ("urn:uuid:xxx") and the short id ("xxx").
    let short_id = id.split(':').last().unwrap_or(&id);
    let cred_path = creds_dir.join(format!("{}.json", short_id));

    if !cred_path.exists() {
        anyhow::bail!("Credential not found: {}", id);
    }

    let content = fs::read_to_string(&cred_path)?;
    let credential: VerifiableCredential = serde_json::from_str(&content)?;

    println!("📋 Credential Details:\n");
    println!("{}", serde_json::to_string_pretty(&credential)?);

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(),
        Commands::Receive { credential } => cmd_receive(credential),
        Commands::List => cmd_list(),
        Commands::Show { id } => cmd_show(id),
    }
}
