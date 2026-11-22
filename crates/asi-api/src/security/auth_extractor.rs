use asi_common::auth::AuthUser;
use asi_common::error::DomainError;
use asi_common::rbac::Permission;
use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user: AuthUser,
    pub request_id: Option<Uuid>,
}

impl AuthenticatedUser {
    pub fn require(&self, permission: Permission, instance: &str) -> Result<(), AppError> {
        if self.user.role.has_permission(permission) {
            Ok(())
        } else {
            Err(AppError::new(
                DomainError::Forbidden(format!(
                    "Role '{}' lacks required permission '{permission:?}'.",
                    self.user.role.as_db_str()
                )),
                self.request_id,
                Some(instance.to_string()),
            ))
        }
    }
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| Uuid::parse_str(s).ok());
        let instance = Some(parts.uri.path().to_string());

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AppError::new(
                    DomainError::Unauthorized("Missing Authorization header.".to_string()),
                    request_id,
                    instance.clone(),
                )
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                AppError::new(
                    DomainError::Unauthorized(
                        "Expected 'Bearer <token>' authorization.".to_string(),
                    ),
                    request_id,
                    instance.clone(),
                )
            })?;

        let claims = state
            .jwt
            .verify_access_token(token)
            .map_err(|err| AppError::new(err, request_id, instance))?;

        let permissions = claims.role.permissions().to_vec();
        Ok(Self {
            user: AuthUser {
                id: claims.sub,
                username: claims.username,
                email: claims.email,
                role: claims.role,
                preferred_locale: claims.preferred_locale,
                permissions,
            },
            request_id,
        })
    }
}
