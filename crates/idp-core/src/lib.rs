// 🧬 The official Rust implementation of the Identity Protocol (IDP) core data structures.
// This crate defines the canonical, in-memory representation of an `.idp` file.
// Specification: v0.2.1

// We bring in the `serde` crate, which we defined in our workspace `Cargo.toml`.
// `Serialize` allows us to turn our structs into text (e.g., YAML, JSON).
// `Deserialize` allows us to turn text back into our structs.
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

// The top-level struct that represents an entire IDP document.
// The `#[derive(...)]` is a macro that automatically implements traits for us.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Identity {
    pub identity: IdentityBlock,
    pub system: SystemBlock,
    pub core: CoreBlock,
    
    // `Option<...>` means this field is optional. An identity might not have credentials yet.
    // `Vec<...>` means it's a list (Vector) of items.
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
    pub created_at: String, // We'll use a proper DateTime type later
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
    
    // `Option<String>` is the correct way to model an optional field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    
    pub proof: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Proof {
    pub proof_id: String,
    #[serde(rename = "type")] // Allows us to use the reserved word `type` as a field name.
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
    pub value: i64, // Use a 64-bit integer for scores
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
// All functions related to an Identity will go here.
impl Identity {
    /// Loads an Identity from a YAML file path.
    ///
    /// # Arguments
    /// * `path` - A reference to a path-like object (e.g., a string)
    ///
    /// # Returns
    /// * `Result<Self, String>` - Returns the parsed Identity on success,
    ///   or an error message string on failure.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        // Open the file at the given path. The `map_err` part converts the
        // standard file I/O error into a simple String for our return type.
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        
        // Create an empty string to hold the file's contents.
        let mut contents = String::new();
        
        // Read the entire file into the `contents` string.
        file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
        
        // Use serde_yaml to parse the string into our Identity struct.
        let identity: Self = serde_yaml::from_str(&contents).map_err(|e| e.to_string())?;
        
        // If all steps succeeded, return the parsed identity wrapped in `Ok`.
        Ok(identity)
    }
}


// This is the standard way to add tests in Rust.
// The code inside this module only gets compiled when we run `cargo test`.
#[cfg(test)]
mod tests {
    use super::*; // Import everything from the parent module.

    #[test]
    fn it_can_be_created() {
        // This is a simple "smoke test". It doesn't check for correctness,
        // only that we can create an instance of our main struct without crashing.
        let identity = Identity {
            identity: IdentityBlock {
                id: "idp:key:123".to_string(),
                version: "0.2.1".to_string(),
                schema_url: "https://idp.org/schemas/v0.2.1".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
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
            // The rest are empty Vecs for this simple test.
            credentials: vec![],
            proofs: vec![],
            contracts: vec![],
            reputation: vec![],
            consent: vec![],
        };

        // `assert_eq!` checks if two values are equal. A powerful tool for testing.
        assert_eq!(identity.core.name, "Clein Pius");
        println!("✅ Smoke test passed: Identity struct created successfully.");
    }

    #[test]
    fn it_can_load_from_a_file() {
        // Create a temporary directory for our test file.
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("clein.idp");

        // A sample IDP file content as a string. Note the `r#""#` syntax
        // which allows for multi-line strings without escaping quotes.
        let sample_idp_content = r#"
identity:
  id: "idp:key:clein_001"
  version: "0.2.1"
  schema_url: "https://idp.org/schemas/v0.2.1"
  created_at: "2024-01-01T00:00:00Z"
  updated_at: "2024-01-01T00:00:00Z"
system:
  public_keys:
    - key_id: "root-key-01"
      algorithm: "Ed25519"
      value: "BASE64_KEY_HERE"
      status: "active"
core:
  name: "Clein Pius"
  bio: "Founder of IDP."
"#;

        // Write the sample content to our temporary file.
        std::fs::write(&file_path, sample_idp_content).unwrap();

        // Call our new function to load the identity from the file.
        let loaded_identity = Identity::load_from_file(&file_path).unwrap();

        // Assert that the loaded data is correct.
        assert_eq!(loaded_identity.identity.id, "idp:key:clein_001");
        assert_eq!(loaded_identity.core.name, "Clein Pius");
        println!("✅ Test passed: Identity loaded successfully from file.");
    }
}
