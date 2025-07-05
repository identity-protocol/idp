// 🧬 The command-line interface for the Identity Protocol.
// This tool allows users to create, manage, and verify their sovereign identity.

use clap::{Parser, Subcommand};
use idp_core::Identity;
use std::path::Path;

/// A sovereign, quantum-resistant identity management tool.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new identity file and its corresponding secret key.
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

    match &cli.command {
        Commands::Init { name, bio } => {
            println!("Forging a new cryptographic identity for '{}'...", name);

            let id_file_name = "my.idp";
            let key_file_name = "my.key";

            // Safety checks
            if Path::new(id_file_name).exists() || Path::new(key_file_name).exists() {
                eprintln!("Error: '{}' or '{}' already exists in this directory.", id_file_name, key_file_name);
                eprintln!("Please move or rename existing files before initializing.");
                return Err("Aborted due to existing files.".to_string());
            }

            // Call our powerful new constructor from idp-core
            match Identity::new(name, bio) {
                Ok((new_identity, private_key_bytes)) => {
                    // Save the public identity file
                    new_identity.save_to_file(id_file_name)?;

                    // Save the secret private key file
                    std::fs::write(key_file_name, &private_key_bytes)
                        .map_err(|e| e.to_string())?;

                    println!("\n✅ Success! Your identity has been created.");
                    println!("  - Public identity saved to: {}", id_file_name);
                    println!("  - Private key saved to:    {}", key_file_name);
                    println!("\nSECURITY WARNING:");
                    println!("  The '{}' file is your secret. It is your password and your soul.", key_file_name);
                    println!("  Guard it. Back it up securely. Never share it with anyone.");
                }
                Err(e) => {
                    eprintln!("Error creating new identity: {}", e);
                    return Err(e);
                }
            }
        }
        Commands::Show => {
            println!("Showing the current identity...");
            // TODO: Implement logic to load and display the file.
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
