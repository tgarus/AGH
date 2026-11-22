use asi_common::error::DomainError;
use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use sqlx::FromRow;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::security::tokens::hash_token;

#[derive(Debug, Clone)]
pub struct AuthenticatedWorker {
    pub worker_id: Uuid,
    pub name: String,
    pub max_concurrency: i32,
    pub request_id: Option<Uuid>,
}

#[derive(FromRow)]
struct WorkerAuthRow {
    id: Uuid,
    name: String,
    max_concurrency: i32,
    status: String,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthenticatedWorker {
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
                    DomainError::Unauthorized("Missing worker Authorization header.".to_string()),
                    request_id,
                    instance.clone(),
                )
            })?;

        let raw_token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                AppError::new(
                    DomainError::Unauthorized("Expected Bearer worker token.".to_string()),
                    request_id,
                    instance.clone(),
                )
            })?;

        let pool = state.db.as_ref().ok_or_else(|| {
            AppError::new(
                DomainError::ServiceUnavailable("Database pool is not configured.".to_string()),
                request_id,
                instance.clone(),
            )
        })?;

        let token_hash = hash_token(raw_token);
        let row: Option<WorkerAuthRow> = sqlx::query_as(
            r#"
            SELECT id, name, max_concurrency, status
            FROM worker_nodes
            WHERE token_hash = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(pool)
        .await
        .map_err(|err| {
            AppError::new(
                DomainError::Internal(format!("worker auth query failed: {err}")),
                request_id,
                instance.clone(),
            )
        })?;

        let Some(row) = row else {
            return Err(AppError::new(
                DomainError::Unauthorized("Invalid worker service token.".to_string()),
                request_id,
                instance,
            ));
        };

        if row.status == "revoked" {
            return Err(AppError::new(
                DomainError::Unauthorized("Worker service token has been revoked.".to_string()),
                request_id,
                instance,
            ));
        }

        Ok(Self {
            worker_id: row.id,
            name: row.name,
            max_concurrency: row.max_concurrency,
            request_id,
        })
    }
}
