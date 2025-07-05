// 🧬 The official Rust implementation of the Identity Protocol (IDP) core data structures.
// This crate defines the canonical, in-memory representation of an `.idp` file
// and provides the core functionality for creating, reading, and writing them.
// Specification: v0.2.1

use data_encoding::BASE64;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

// Make the crypto module public so the CLI can access it if needed.
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
    pub created_at: String,
    pub updated_at: String,
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
    /// This is the main entry point for creating a new IDP.
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
        // For now, we are still using a placeholder. We will integrate a proper time library later.
        let now_iso = "2024-01-01T00:00:00Z"; 

        // 4. Construct the full Identity struct.
        let new_identity = Identity {
            identity: IdentityBlock {
                id, // Use the new, real ID
                version: "0.2.1".to_string(),
                schema_url: "https://idp.org/schemas/v0.2.1".to_string(),
                created_at: now_iso.to_string(),
                updated_at: now_iso.to_string(),
            },
            system: SystemBlock {
                public_keys: vec![public_key], // Use the new, real public key
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
        // This test has been superseded by the `it_can_create_with_new_constructor` test,
        // but we keep it as a simple smoke test for struct instantiation.
        let identity = Identity {
            identity: IdentityBlock {
                id: "idp:key:123".to_string(),
                version: "0.2.1".to_string(),
                schema_url: "https://idp.org/schemas/v0.2.1".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            },
            system: SystemBlock { public_keys: vec![] },
            core: CoreBlock { name: "Test User".to_string(), bio: "Test Bio".to_string() },
            credentials: vec![],
            proofs: vec![],
            contracts: vec![],
            reputation: vec![],
            consent: vec![],
        };
        assert_eq!(identity.core.name, "Test User");
    }

    #[test]
    fn it_can_load_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test_load.idp");
        let sample_idp_content = r#"
identity:
  id: "idp:key:clein_001"
  version: "0.2.1"
  schema_url: "https://idp.org/schemas/v0.2.1"
  created_at: "2024-01-01T00:00:00Z"
  updated_at: "2024-01-01T00:00:00Z"
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
    }

    #[test]
    fn it_can_perform_a_save_and_load_round_trip() {
        let original_identity = Identity::new("Round Trip User", "Testing the save/load cycle.").unwrap().0;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("round_trip.idp");
        
        original_identity.save_to_file(&file_path).unwrap();
        let loaded_identity = Identity::load_from_file(&file_path).unwrap();
        
        assert_eq!(original_identity, loaded_identity);
    }

    #[test]
    fn new_constructor_creates_valid_identity() {
        let (identity, private_key) = Identity::new("Constructor Test", "Bio for constructor").unwrap();

        // 1. Check if the identity ID looks correct
        assert!(identity.identity.id.starts_with("idp:key:sha256:"));

        // 2. Check if the system block contains exactly one public key
        assert_eq!(identity.system.public_keys.len(), 1);
        let public_key = &identity.system.public_keys[0];
        assert_eq!(public_key.algorithm, "Ed25519");
        assert_eq!(public_key.status, "active");
        assert!(!public_key.value.is_empty()); // Ensure the key value is not empty

        // 3. Check if core data is populated
        assert_eq!(identity.core.name, "Constructor Test");

        // 4. Check if the private key has a reasonable length
        // Ed25519 PKCS#8 private keys are typically around 85-87 bytes.
        assert!(private_key.len() > 80 && private_key.len() < 90);

        println!("✅ Test passed: Identity::new() constructor works as expected.");
    }
}
