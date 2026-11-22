use std::sync::OnceLock;

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use asi_common::error::DomainError;
use rand::rngs::OsRng;

const ARGON2_M_COST_KIB: u32 = 19_456;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

static DUMMY_HASH: OnceLock<String> = OnceLock::new();

fn build_argon2() -> Result<Argon2<'static>, DomainError> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|err| DomainError::Internal(format!("invalid argon2 parameters: {err}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub fn hash_password(password: &str) -> Result<String, DomainError> {
    let argon2 = build_argon2()?;
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| DomainError::Internal(format!("password hashing failed: {err}")))?;
    Ok(hash.to_string())
}

#[must_use]
pub fn verify_password(password: &str, phc_hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(phc_hash) else {
        return false;
    };
    let Ok(argon2) = build_argon2() else {
        return false;
    };
    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Runs a dummy Argon2id verification to equalize response timing for unknown usernames.
pub fn verify_dummy_password(password: &str) {
    let dummy = DUMMY_HASH.get_or_init(|| {
        hash_password("asi-dummy-timing-guard-password")
            .unwrap_or_else(|_| "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string())
    });
    let _ = verify_password(password, dummy);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies_password() {
        let hash = hash_password("StrongPassword_123!").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("StrongPassword_123!", &hash));
        assert!(!verify_password("wrong-password", &hash));
        verify_dummy_password("anything");
    }
}
