// 🧬 The official Rust implementation of the Identity Protocol (IDP) core data structures.
// This crate defines the canonical, in-memory representation of an `.idp` file
// and provides the core functionality for reading and writing them.
// Specification: v0.2.1

use chrono::{DateTime, Utc};
use data_encoding::BASE64;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub mod crypto;

// The top-level struct that represents an entire IDP document.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Identity {
    pub identity: IdentityBlock,
    pub system: SystemBlock,
    pub core: CoreBlock,
    
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
    
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contracts: Vec<Contract>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reputation: Vec<Reputation>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent: Vec<Consent>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentityBlock {
    pub id: String,
    pub version: String,
    pub schema_url: String,
    pub created_at: DateTime<Utc>, // Changed from String
    pub updated_at: DateTime<Utc>, // Changed from String
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SystemBlock {
    pub public_keys: Vec<PublicKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PublicKey {
    pub key_id: String,
    pub algorithm: String,
    pub value: String, // Base64 encoded public key
    pub status: String, // "active" or "revoked"
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CoreBlock {
    pub name: String,
    pub bio: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Credential {
    pub claim: String,
    pub issued_by: String,
    pub issued_at: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    
    pub proof: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Proof {
    pub proof_id: String,
    #[serde(rename = "type")]
    pub proof_type: String,
    pub claim_hash: String,
    pub signed_by: Signer,
    pub signature: Vec<SignatureComponent>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Signer {
    pub idp_id: String,
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignatureComponent {
    pub algorithm: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Contract {
    pub contract_id: String,
    pub status: String,
    pub parties: Vec<String>,
    pub terms: String,
    pub consequence: Consequence,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Consequence {
    pub on_success: String,
    pub on_failure: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Reputation {
    pub score_name: String,
    pub value: i64,
    pub history: Vec<ReputationEvent>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ReputationEvent {
    pub event: String,
    pub change: i64,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Consent {
    pub granted_to: String,
    pub fields: Vec<String>,
    pub expires_at: String,
    pub purpose: String,
}

// Implementation block for the Identity struct.
impl Identity {
    /// Creates a new Identity instance, generating a new cryptographic key pair.
    /// Returns the new Identity and the secret private key bytes.
    pub fn new(name: &str, bio: &str) -> Result<(Self, Vec<u8>), String> {
        // 1. Generate the cryptographic foundation.
        let key_pair = crypto::generate_ed25519_keypair()?;
        let public_key = key_pair.public_key;
        let private_key_bytes = key_pair.private_key_bytes;

        // 2. Create the unique ID by hashing the public key.
        let public_key_hash = digest::digest(&digest::SHA256, public_key.value.as_bytes());
        let id = format!("idp:key:sha256:{}", BASE64.encode(public_key_hash.as_ref()));

        // 3. Get a real timestamp.
        let now: DateTime<Utc> = Utc::now();

        // 4. Construct the full Identity struct.
        let new_identity = Identity {
            identity: IdentityBlock {
                id,
                version: "0.2.1".to_string(),
                schema_url: "https://idp.org/schemas/v0.2.1".to_string(),
                created_at: now,
                updated_at: now,
            },
            system: SystemBlock {
                public_keys: vec![public_key],
            },
            core: CoreBlock {
                name: name.to_string(),
                bio: bio.to_string(),
            },
            credentials: vec![],
            proofs: vec![],
            contracts: vec![],
            reputation: vec![],
            consent: vec![],
        };

        // 5. Return both the public identity and the secret private key.
        Ok((new_identity, private_key_bytes))
    }

    /// Loads an Identity from a YAML file path.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
        let identity: Self = serde_yaml::from_str(&contents).map_err(|e| e.to_string())?;
        Ok(identity)
    }

    /// Serializes the Identity struct to YAML and saves it to a file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let yaml_string = serde_yaml::to_string(self).map_err(|e| e.to_string())?;
        let mut file = File::create(path).map_err(|e| e.to_string())?;
        file.write_all(yaml_string.as_bytes()).map_err(|e| e.to_string())?;
        Ok(())
    }
}

// This module contains all tests for the idp-core library.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_can_be_created() {
        let identity = Identity {
            identity: IdentityBlock {
                id: "idp:key:123".to_string(),
                version: "0.2.1".to_string(),
                schema_url: "https://idp.org/schemas/v0.2.1".to_string(),
                created_at: Utc::now(), // Updated to use chrono
                updated_at: Utc::now(), // Updated to use chrono
            },
            system: SystemBlock {
                public_keys: vec![PublicKey {
                    key_id: "root-key-01".to_string(),
                    algorithm: "Ed25519".to_string(),
                    value: "BASE64_KEY_HERE".to_string(),
                    status: "active".to_string(),
                }],
            },
            core: CoreBlock {
                name: "Clein Pius".to_string(),
                bio: "Founder of IDP.".to_string(),
            },
            credentials: vec![],
            proofs: vec![],
            contracts: vec![],
            reputation: vec![],
            consent: vec![],
        };
        assert_eq!(identity.core.name, "Clein Pius");
        println!("✅ Smoke test passed: Identity struct created successfully.");
    }

    #[test]
    fn it_can_load_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("clein.idp");
        // Using a real timestamp string format that serde_yaml + chrono can parse.
        let sample_idp_content = r#"
identity:
  id: "idp:key:clein_001"
  version: "0.2.1"
  schema_url: "https://idp.org/schemas/v0.2.1"
  created_at: "2024-07-06T10:00:00Z" 
  updated_at: "2024-07-06T10:00:00Z"
system:
  public_keys: []
core:
  name: "Clein Pius"
  bio: "Founder of IDP."
"#;
        std::fs::write(&file_path, sample_idp_content).unwrap();
        let loaded_identity = Identity::load_from_file(&file_path).unwrap();
        assert_eq!(loaded_identity.identity.id, "idp:key:clein_001");
        assert_eq!(loaded_identity.core.name, "Clein Pius");
        println!("✅ Test passed: Identity loaded successfully from file.");
    }

    #[test]
    fn it_can_perform_a_save_and_load_round_trip() {
        // 1. SETUP
        let original_identity = Identity::new("Round Trip User", "Testing the save/load cycle.").unwrap().0;
        
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("round_trip.idp");
        
        // 2. ACTION 1: Save
        original_identity.save_to_file(&file_path).unwrap();
        
        // 3. ACTION 2: Load
        let loaded_identity = Identity::load_from_file(&file_path).unwrap();
        
        // 4. VERIFICATION
        assert_eq!(original_identity, loaded_identity);
        println!("✅ Test passed: Save/load round-trip completed successfully.");
    }
}
