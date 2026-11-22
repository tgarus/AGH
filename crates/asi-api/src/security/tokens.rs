use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

#[must_use]
pub fn generate_opaque_token(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", hex::encode(bytes))
}

#[must_use]
pub fn hash_token(raw_token: &str) -> String {
    let digest = Sha256::digest(raw_token.as_bytes());
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_tokens_and_deterministic_hashes() {
        let t1 = generate_opaque_token("asiw_");
        let t2 = generate_opaque_token("asiw_");
        assert!(t1.starts_with("asiw_"));
        assert_eq!(t1.len(), 5 + 64);
        assert_ne!(t1, t2);
        assert_eq!(hash_token(&t1), hash_token(&t1));
        assert_eq!(hash_token(&t1).len(), 64);
    }
}
