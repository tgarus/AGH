use std::net::IpAddr;

use asi_common::error::DomainError;
use asi_common::rbac::Role;
use axum::http::HeaderMap;
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::security::auth_extractor::AuthenticatedUser;

#[must_use]
pub fn extract_request_id(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

#[must_use]
pub fn extract_source_ip(headers: &HeaderMap) -> Option<IpNetwork> {
    let raw = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))?;
    raw.trim().parse::<IpAddr>().ok().map(IpNetwork::from)
}

#[must_use]
pub fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect())
}

pub fn require_db<'a>(
    state: &'a AppState,
    request_id: Option<Uuid>,
    instance: &str,
) -> Result<&'a PgPool, AppError> {
    state.db.as_ref().ok_or_else(|| {
        AppError::new(
            DomainError::ServiceUnavailable("Database pool is not configured.".to_string()),
            request_id,
            Some(instance.to_string()),
        )
    })
}

#[must_use]
pub fn map_db_err(
    err: sqlx::Error,
    conflict_msg: &str,
    request_id: Option<Uuid>,
    instance: &str,
) -> AppError {
    let domain = match err.as_database_error().and_then(|d| d.code()) {
        Some(code) if code == "23505" => DomainError::Conflict(conflict_msg.to_string()),
        Some(code) if code == "23503" => DomainError::Conflict(
            "Referenced resource does not exist or is currently in use.".to_string(),
        ),
        _ => DomainError::Internal(format!("database error: {err}")),
    };
    AppError::new(domain, request_id, Some(instance.to_string()))
}

/// Verifies that the authenticated user can access the given asset group.
/// Admins always have access; non-admins can access groups with no explicit
/// member restrictions or where they appear in `asset_group_members`.
pub(crate) async fn ensure_user_group_access(
    pool: &PgPool,
    auth: &AuthenticatedUser,
    asset_group_id: Uuid,
    instance: &str,
) -> Result<(), AppError> {
    if auth.user.role == Role::Admin {
        return Ok(());
    }
    let allowed: bool = sqlx::query_scalar(
        r#"
        SELECT NOT EXISTS (SELECT 1 FROM asset_group_members WHERE asset_group_id = $1)
            OR EXISTS (SELECT 1 FROM asset_group_members WHERE asset_group_id = $1 AND user_id = $2)
        "#,
    )
    .bind(asset_group_id)
    .bind(auth.user.id)
    .fetch_one(pool)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "asset group access check failed",
            auth.request_id,
            instance,
        )
    })?;

    if !allowed {
        return Err(AppError::new(
            DomainError::Forbidden("You do not have access to this asset group.".to_string()),
            auth.request_id,
            Some(instance.to_string()),
        ));
    }
    Ok(())
}
