// 🧬 The command-line interface for the Identity Protocol.
// This tool allows users to create, manage, and verify their sovereign identity.

use clap::{Parser, Subcommand};
// We import the full suite of structs needed to construct and load an Identity.
use idp_core::Identity;

use std::path::Path; // To handle the file path

/// A sovereign, quantum-resistant identity management tool.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new identity file in the current directory.
    Init {
        /// The full name for the new identity.
        #[arg(short, long)]
        name: String,

        /// A short bio for the new identity.
        #[arg(short, long)]
        bio: String,
    },
    /// Show the contents of the identity file.
    Show,
    /// Set a value in the identity file.
    Set {
        /// The path to the value to set (e.g., "core.bio").
        path: String,
        /// The new value.
        value: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let id_file_name = "my.idp";
    let key_file_name = "my.key";

    // Match the subcommand provided by the user and execute the corresponding logic.
    match &cli.command {
        Commands::Init { name, bio } => {
            println!("Forging a new cryptographic identity for '{}'...", name);

            // Safety checks
            if Path::new(id_file_name).exists() || Path::new(key_file_name).exists() {
                eprintln!("Error: '{}' or '{}' already exists.", id_file_name, key_file_name);
                eprintln!("Please move or rename existing files before initializing.");
                return Err("Aborted due to existing files.".to_string());
            }

            // Call our powerful constructor from idp-core
            match Identity::new(name, bio) {
                Ok((new_identity, private_key_bytes)) => {
                    // Save the public identity file
                    new_identity.save_to_file(id_file_name)?;

                    // Save the secret private key file
                    std::fs::write(key_file_name, &private_key_bytes)
                        .map_err(|e| e.to_string())?;

                    println!("✅ Success! Your identity has been created.");
                    println!("  - Public identity saved to: {}", id_file_name);
                    println!("  - Private key saved to:    {}", key_file_name);
                    println!("\nSECURITY WARNING:");
                    println!("  The 'my.key' file is your secret. It is your password and your soul.");
                    println!("  Guard it. Back it up securely. Never share it with anyone.");
                }
                Err(e) => {
                    eprintln!("Error creating new identity: {}", e);
                    return Err(e);
                }
            }
        }
        Commands::Show => {
            println!("🔎 Reading identity from '{}'...", id_file_name);

            // Use our powerful core library function to load the identity from disk.
            match Identity::load_from_file(id_file_name) {
                Ok(identity) => {
                    // If loading succeeds, print a beautifully formatted summary.
                    println!("\n--- 🧬 Sovereign Identity ---");
                    println!("  ID:        {}", identity.identity.id);
                    println!("  Name:      {}", identity.core.name);
                    println!("  Bio:       {}", identity.core.bio);
                    println!("----------------------------");
                    println!("  Keys:      {} (Spec v{})", identity.system.public_keys.len(), identity.identity.version);
                    println!("  Created:   {}", identity.identity.created_at);
                    println!("----------------------------");
                }
                Err(e) => {
                    // If loading fails, print a helpful error message to standard error.
                    eprintln!("\nError: Failed to load identity file.");
                    eprintln!("  Reason: {}", e);
                    eprintln!("\nHint: Have you run `idp init` in this directory?");
                    return Err("Failed to load identity.".to_string());
                }
            }
        }
        Commands::Set { path, value } => {
            println!("Setting a value...");
            println!("  Path: {}", path);
            println!("  Value: {}", value);
            // TODO: Implement logic to load, modify, and save the file.
        }
    }

    Ok(())
}
