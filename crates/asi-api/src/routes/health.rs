use asi_common::error::{DomainError, ProblemDetails};
use asi_common::health::{ComponentStatus, HealthResponse, ReadinessResponse};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use utoipa::OpenApi;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::openapi::ApiDoc;

fn extract_request_id(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

#[utoipa::path(
    get,
    path = "/api/v1/healthz",
    tag = "System",
    responses(
        (status = 200, description = "Service process is alive", body = HealthResponse)
    )
)]
pub async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "asi-api".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/readyz",
    tag = "System",
    responses(
        (status = 200, description = "API and PostgreSQL database are ready", body = ReadinessResponse),
        (status = 503, description = "Database unavailable", body = ProblemDetails)
    )
)]
pub async fn readyz(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ReadinessResponse>, AppError> {
    let request_id = extract_request_id(&headers);
    let pool = state.db.as_ref().ok_or_else(|| {
        AppError::new(
            DomainError::ServiceUnavailable("Database pool is not configured.".to_string()),
            request_id,
            Some("/api/v1/readyz".to_string()),
        )
    })?;

    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "database readiness probe failed");
            AppError::new(
                DomainError::ServiceUnavailable("Database connectivity check failed.".to_string()),
                request_id,
                Some("/api/v1/readyz".to_string()),
            )
        })?;

    Ok(Json(ReadinessResponse {
        status: ComponentStatus::Ok,
        database: ComponentStatus::Ok,
        timestamp: Utc::now(),
    }))
}

pub async fn openapi_json(headers: HeaderMap) -> Result<impl IntoResponse, AppError> {
    let request_id = extract_request_id(&headers);
    let json = ApiDoc::openapi().to_pretty_json().map_err(|err| {
        AppError::new(
            DomainError::Internal(format!("failed to serialize OpenAPI spec: {err}")),
            request_id,
            Some("/api/v1/openapi.json".to_string()),
        )
    })?;

    Ok((
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        json,
    ))
}
