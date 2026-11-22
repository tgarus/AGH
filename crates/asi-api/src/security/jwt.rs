use asi_common::auth::AuthUser;
use asi_common::error::DomainError;
use asi_common::rbac::Role;
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const ACCESS_TOKEN_TTL_SECONDS: u64 = 15 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: Uuid,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub preferred_locale: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Clone)]
pub struct JwtManager {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtManager {
    #[must_use]
    pub fn new(secret: &str) -> Self {
        let bytes = secret.as_bytes();
        Self {
            encoding: EncodingKey::from_secret(bytes),
            decoding: DecodingKey::from_secret(bytes),
        }
    }

    pub fn issue_access_token(&self, user: &AuthUser) -> Result<String, DomainError> {
        let now_ts = Utc::now().timestamp();
        let iat = usize::try_from(now_ts.max(0))
            .map_err(|_| DomainError::Internal("invalid system clock for JWT".to_string()))?;
        let ttl = usize::try_from(ACCESS_TOKEN_TTL_SECONDS)
            .map_err(|_| DomainError::Internal("invalid JWT TTL".to_string()))?;
        let claims = AccessClaims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            role: user.role,
            preferred_locale: user.preferred_locale.clone(),
            iat,
            exp: iat.saturating_add(ttl),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|err| DomainError::Internal(format!("JWT signing failed: {err}")))
    }

    pub fn verify_access_token(&self, token: &str) -> Result<AccessClaims, DomainError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let data = decode::<AccessClaims>(token, &self.decoding, &validation).map_err(|_| {
            DomainError::Unauthorized("Invalid or expired access token.".to_string())
        })?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user(role: Role) -> AuthUser {
        AuthUser {
            id: Uuid::new_v4(),
            username: "analyst".to_string(),
            email: "analyst@agh.local".to_string(),
            role,
            preferred_locale: "pl".to_string(),
            permissions: role.permissions().to_vec(),
        }
    }

    #[test]
    fn issues_and_verifies_valid_jwt() {
        let mgr = JwtManager::new("test-secret-at-least-32-bytes-long!!");
        let user = sample_user(Role::ReadWrite);
        let token = mgr.issue_access_token(&user).unwrap();
        let claims = mgr.verify_access_token(&token).unwrap();

        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.username, "analyst");
        assert_eq!(claims.role, Role::ReadWrite);
    }

    #[test]
    fn rejects_tampered_or_wrong_secret_jwt() {
        let mgr1 = JwtManager::new("secret-one-at-least-32-bytes-long!");
        let mgr2 = JwtManager::new("secret-two-at-least-32-bytes-long!");
        let token = mgr1.issue_access_token(&sample_user(Role::Admin)).unwrap();

        assert!(mgr2.verify_access_token(&token).is_err());
        assert!(mgr1.verify_access_token("not.a.jwt").is_err());
    }
}
