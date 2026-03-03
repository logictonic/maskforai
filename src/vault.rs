//! Encrypted vault for whistledown mappings.
//!
//! Uses AES-256-GCM for encryption and Argon2id for key derivation.
//! Stores mappings on disk so they survive proxy restarts.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Argon2, Algorithm, Params, Version};
use rand::RngCore;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Salt length in bytes.
const SALT_LEN: usize = 16;
/// Nonce length for AES-256-GCM (96 bits).
const NONCE_LEN: usize = 12;

/// Encrypted vault for storing whistledown forward/reverse maps.
pub struct Vault {
    path: PathBuf,
    key: [u8; 32],
}

/// Vault data format: salt(16) + nonce(12) + ciphertext(variable).
impl Vault {
    /// Create a new vault with a password-derived key.
    pub fn new(path: PathBuf, password: &str) -> Self {
        // Read existing salt or generate new one
        let salt = if path.exists() {
            if let Ok(data) = fs::read(&path) {
                if data.len() >= SALT_LEN {
                    let mut s = [0u8; SALT_LEN];
                    s.copy_from_slice(&data[..SALT_LEN]);
                    s
                } else {
                    generate_salt()
                }
            } else {
                generate_salt()
            }
        } else {
            generate_salt()
        };

        let key = derive_key(password, &salt);
        Self { path, key }
    }

    /// Create a vault with a raw key (for testing / machine-generated keys).
    pub fn with_key(path: PathBuf, key: [u8; 32]) -> Self {
        Self { path, key }
    }

    /// Save mappings to encrypted file.
    pub fn save(&self, forward: &HashMap<String, String>, reverse: &HashMap<String, String>) -> Result<(), VaultError> {
        let data = VaultData { forward: forward.clone(), reverse: reverse.clone() };
        let json = serde_json::to_vec(&data).map_err(|e| VaultError::Serialize(e.to_string()))?;

        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Re-derive key with new salt
        let key = derive_key_raw(&self.key, &salt);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, json.as_ref())
            .map_err(|e| VaultError::Crypto(e.to_string()))?;

        // Write: salt + nonce + ciphertext
        let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        // Create parent directory if needed
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| VaultError::Io(e.to_string()))?;
        }
        fs::write(&self.path, &output).map_err(|e| VaultError::Io(e.to_string()))?;

        Ok(())
    }

    /// Load mappings from encrypted file.
    pub fn load(&self) -> Result<(HashMap<String, String>, HashMap<String, String>), VaultError> {
        if !self.path.exists() {
            return Ok((HashMap::new(), HashMap::new()));
        }

        let data = fs::read(&self.path).map_err(|e| VaultError::Io(e.to_string()))?;
        if data.len() < SALT_LEN + NONCE_LEN + 1 {
            return Err(VaultError::Corrupt("File too short".into()));
        }

        let salt = &data[..SALT_LEN];
        let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ciphertext = &data[SALT_LEN + NONCE_LEN..];

        let key = derive_key_raw(&self.key, salt);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::Crypto("Decryption failed (wrong password?)".into()))?;

        let vault_data: VaultData = serde_json::from_slice(&plaintext)
            .map_err(|e| VaultError::Serialize(e.to_string()))?;

        Ok((vault_data.forward, vault_data.reverse))
    }

    /// Check if vault file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Delete vault file.
    pub fn delete(&self) -> Result<(), VaultError> {
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|e| VaultError::Io(e.to_string()))?;
        }
        Ok(())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VaultData {
    forward: HashMap<String, String>,
    reverse: HashMap<String, String>,
}

#[derive(Debug)]
pub enum VaultError {
    Io(String),
    Crypto(String),
    Serialize(String),
    Corrupt(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "vault IO error: {}", e),
            VaultError::Crypto(e) => write!(f, "vault crypto error: {}", e),
            VaultError::Serialize(e) => write!(f, "vault serialization error: {}", e),
            VaultError::Corrupt(e) => write!(f, "vault corrupt: {}", e),
        }
    }
}

impl std::error::Error for VaultError {}

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive a 256-bit key from password + salt using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(
        19456,  // 19 MiB memory
        2,      // 2 iterations
        1,      // 1 degree of parallelism
        Some(32),
    ).expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 key derivation failed");
    key
}

/// Derive encryption key from master key + per-file salt (simple HKDF-like).
fn derive_key_raw(master: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(master);
    hasher.update(salt);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_vault_path(name: &str) -> PathBuf {
        env::temp_dir().join(format!("maskforai-vault-test-{}", name))
    }

    #[test]
    fn vault_roundtrip() {
        let path = temp_vault_path("roundtrip");
        let _ = fs::remove_file(&path);

        let vault = Vault::new(path.clone(), "test-password-123");

        let mut forward = HashMap::new();
        forward.insert("user@test.com".into(), "[[EMAIL_1]]".into());
        forward.insert("+79991234567".into(), "[[PHONE_1]]".into());

        let mut reverse = HashMap::new();
        reverse.insert("[[EMAIL_1]]".into(), "user@test.com".into());
        reverse.insert("[[PHONE_1]]".into(), "+79991234567".into());

        vault.save(&forward, &reverse).unwrap();
        assert!(path.exists());

        let (loaded_fwd, loaded_rev) = vault.load().unwrap();
        assert_eq!(loaded_fwd, forward);
        assert_eq!(loaded_rev, reverse);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn vault_wrong_password_fails() {
        let path = temp_vault_path("wrong-pw");
        let _ = fs::remove_file(&path);

        let vault1 = Vault::new(path.clone(), "correct-password");
        let mut forward = HashMap::new();
        forward.insert("secret".into(), "[[DATA_1]]".into());
        vault1.save(&forward, &HashMap::new()).unwrap();

        let vault2 = Vault::new(path.clone(), "wrong-password");
        let result = vault2.load();
        assert!(result.is_err(), "Should fail with wrong password");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn vault_empty_file_returns_empty_maps() {
        let path = temp_vault_path("nonexistent");
        let _ = fs::remove_file(&path);

        let vault = Vault::new(path, "any-password");
        let (fwd, rev) = vault.load().unwrap();
        assert!(fwd.is_empty());
        assert!(rev.is_empty());
    }

    #[test]
    fn vault_delete() {
        let path = temp_vault_path("delete");
        let _ = fs::remove_file(&path);

        let vault = Vault::new(path.clone(), "pw");
        vault.save(&HashMap::new(), &HashMap::new()).unwrap();
        assert!(path.exists());

        vault.delete().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn vault_with_raw_key() {
        let path = temp_vault_path("raw-key");
        let _ = fs::remove_file(&path);

        let key = [42u8; 32];
        let vault = Vault::with_key(path.clone(), key);

        let mut forward = HashMap::new();
        forward.insert("data".into(), "token".into());
        vault.save(&forward, &HashMap::new()).unwrap();

        let vault2 = Vault::with_key(path.clone(), key);
        let (loaded, _) = vault2.load().unwrap();
        assert_eq!(loaded.get("data").unwrap(), "token");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn vault_corrupt_data_fails() {
        let path = temp_vault_path("corrupt");
        let _ = fs::remove_file(&path);

        // Write garbage
        fs::write(&path, b"too short").unwrap();
        let vault = Vault::new(path.clone(), "pw");
        let result = vault.load();
        assert!(result.is_err());

        let _ = fs::remove_file(&path);
    }
}
