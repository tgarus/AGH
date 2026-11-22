use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use asi_common::error::DomainError;
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clone)]
pub struct SecretBox {
    cipher: Aes256Gcm,
}

impl SecretBox {
    #[must_use]
    pub fn dev_default() -> Self {
        let key = aes_gcm::Key::<Aes256Gcm>::from([0u8; 32]);
        Self {
            cipher: Aes256Gcm::new(&key),
        }
    }

    pub fn from_hex_key(hex_key: &str) -> Result<Self> {
        let raw = hex::decode(hex_key.trim()).context("ASI_MASTER_KEY must be valid hex")?;
        if raw.len() != 32 {
            bail!("ASI_MASTER_KEY must decode to exactly 32 bytes (64 hex chars)");
        }
        let cipher = Aes256Gcm::new_from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key length"))?;
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DomainError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| DomainError::Internal("secret encryption failed".to_string()))?;
        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>, DomainError> {
        if nonce_bytes.len() != 12 {
            return Err(DomainError::Internal(
                "invalid secret nonce length".to_string(),
            ));
        }
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| DomainError::Internal("secret decryption failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const KEY_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    #[test]
    fn round_trips_and_rejects_tampering() {
        let box_a = SecretBox::from_hex_key(KEY_A).unwrap();
        let box_b = SecretBox::from_hex_key(KEY_B).unwrap();

        let (mut ct, nonce) = box_a.encrypt(b"webhook-secret-token").unwrap();
        let pt = box_a.decrypt(&ct, &nonce).unwrap();
        assert_eq!(pt, b"webhook-secret-token");

        assert!(box_b.decrypt(&ct, &nonce).is_err());
        ct[0] ^= 0xff;
        assert!(box_a.decrypt(&ct, &nonce).is_err());
    }
}
