use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::rbac::{Permission, Role};

#[derive(Clone, Deserialize, Serialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub preferred_locale: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in_seconds: u64,
    pub user: AuthUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserSummary {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub is_active: bool,
    pub preferred_locale: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Deserialize, Serialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub role: Role,
    pub preferred_locale: Option<String>,
}

impl fmt::Debug for CreateUserRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateUserRequest")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("role", &self.role)
            .field("preferred_locale", &self.preferred_locale)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize, ToSchema)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub role: Option<Role>,
    pub is_active: Option<bool>,
    pub preferred_locale: Option<String>,
    pub password: Option<String>,
}

impl fmt::Debug for UpdateUserRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateUserRequest")
            .field("email", &self.email)
            .field("role", &self.role)
            .field("is_active", &self.is_active)
            .field("preferred_locale", &self.preferred_locale)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}
