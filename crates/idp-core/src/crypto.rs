// crates/idp-core/src/crypto.rs

use data_encoding::BASE64;
use ring::{
    rand,
    signature::{self, KeyPair},
};
use crate::PublicKey; // Use the PublicKey struct from our lib.rs

// This struct will hold the results of key generation.
// We explicitly separate the public part (safe to share) from the private part (secret).
pub struct GeneratedKeyPair {
    pub public_key: PublicKey,
    pub private_key_bytes: Vec<u8>,
}

/// Generates a new Ed25519 key pair.
pub fn generate_ed25519_keypair() -> Result<GeneratedKeyPair, String> {
    let rng = rand::SystemRandom::new();
    
    // Generate the key pair PKCS#8 document, which is a standard format.
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| e.to_string())?;

    // Create a key pair object from the raw bytes.
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|e| e.to_string())?;
        
    // Get the public key bytes and encode them as a Base64 string.
    let public_key_bytes = key_pair.public_key().as_ref();
    let public_key_base64 = BASE64.encode(public_key_bytes);

    // Construct the PublicKey struct that will be stored in the .idp file.
    let public_key_struct = PublicKey {
        key_id: "root-key-01".to_string(),
        algorithm: "Ed25519".to_string(),
        value: public_key_base64,
        status: "active".to_string(),
    };

    Ok(GeneratedKeyPair {
        public_key: public_key_struct,
        private_key_bytes: pkcs8_bytes.as_ref().to_vec(),
    })
}
