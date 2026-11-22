use asi_common::assets::{
    CreateWorkerTokenRequest, CreateWorkerTokenResponse, WorkerNodeDto, WorkerNodeStatus,
};
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::routes::common::{extract_source_ip, map_db_err, require_db};
use crate::security::auth_extractor::AuthenticatedUser;
use crate::security::tokens::{generate_opaque_token, hash_token};

#[derive(FromRow)]
struct WorkerNodeRow {
    id: Uuid,
    name: String,
    segment_tag: Option<String>,
    status: String,
    capabilities: serde_json::Value,
    max_concurrency: i32,
    last_heartbeat_at: Option<DateTime<Utc>>,
    registered_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl WorkerNodeRow {
    fn into_dto(self, request_id: Option<Uuid>, instance: &str) -> Result<WorkerNodeDto, AppError> {
        let status = WorkerNodeStatus::from_db_str(&self.status).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("unknown worker status '{}'", self.status)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(WorkerNodeDto {
            id: self.id,
            name: self.name,
            segment_tag: self.segment_tag,
            status,
            capabilities: self.capabilities,
            max_concurrency: self.max_concurrency,
            last_heartbeat_at: self.last_heartbeat_at,
            registered_at: self.registered_at,
            revoked_at: self.revoked_at,
        })
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/workers",
    tag = "Workers",
    security(("bearer_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated worker nodes", body = PaginatedResponse<WorkerNodeDto>),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn list_workers(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<WorkerNodeDto>>, AppError> {
    let instance = "/api/v1/workers";
    auth.require(Permission::ManageWorkers, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let pg = query.sanitized();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_nodes")
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "count failed", auth.request_id, instance))?;

    let rows: Vec<WorkerNodeRow> = sqlx::query_as(
        r#"
        SELECT id, name, segment_tag, status, capabilities, max_concurrency, last_heartbeat_at, registered_at, revoked_at
        FROM worker_nodes
        ORDER BY registered_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "query failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;
    let total_u64 = u64::try_from(total.max(0)).unwrap_or(0);

    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(pg.page, pg.per_page, total_u64),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/workers/tokens",
    tag = "Workers",
    security(("bearer_auth" = [])),
    request_body = CreateWorkerTokenRequest,
    responses(
        (status = 201, description = "Worker node provisioned with one-time bearer token", body = CreateWorkerTokenResponse),
        (status = 409, description = "Worker name already exists", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn create_worker_token(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateWorkerTokenRequest>,
) -> Result<(StatusCode, Json<CreateWorkerTokenResponse>), AppError> {
    let instance = "/api/v1/workers/tokens";
    auth.require(Permission::ManageWorkers, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let name = payload.name.trim().to_string();
    let max_concurrency = payload.max_concurrency.unwrap_or(2);
    let mut violations = Vec::new();
    if name.is_empty() {
        violations.push(FieldViolation {
            field: "name".to_string(),
            code: "REQUIRED".to_string(),
            message: "Worker name cannot be empty.".to_string(),
        });
    }
    if max_concurrency < 1 {
        violations.push(FieldViolation {
            field: "max_concurrency".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "max_concurrency must be >= 1.".to_string(),
        });
    }
    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Worker registration failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let raw_token = generate_opaque_token("asiw_");
    let token_hash = hash_token(&raw_token);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, instance))?;

    let row: WorkerNodeRow = sqlx::query_as(
        r#"
        INSERT INTO worker_nodes (name, segment_tag, token_hash, status, max_concurrency)
        VALUES ($1, $2, $3, 'offline', $4)
        RETURNING id, name, segment_tag, status, capabilities, max_concurrency, last_heartbeat_at, registered_at, revoked_at
        "#,
    )
    .bind(&name)
    .bind(payload.segment_tag.map(|s| s.trim().to_string()))
    .bind(&token_hash)
    .bind(max_concurrency)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "Worker node name already exists.", auth.request_id, instance))?;

    let dto = row.into_dto(auth.request_id, instance)?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "worker_token.created",
            resource_type: "worker_node",
            resource_id: Some(dto.id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "name": dto.name,
                "segment_tag": dto.segment_tag,
                "max_concurrency": dto.max_concurrency,
            })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, instance))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateWorkerTokenResponse {
            worker: dto,
            token: raw_token,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/workers/{id}/revoke",
    tag = "Workers",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Worker node UUID")),
    responses(
        (status = 200, description = "Worker token revoked", body = WorkerNodeDto),
        (status = 404, description = "Worker node not found", body = ProblemDetails)
    )
)]
pub async fn revoke_worker(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkerNodeDto>, AppError> {
    let instance = format!("/api/v1/workers/{id}/revoke");
    auth.require(Permission::ManageWorkers, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let row: Option<WorkerNodeRow> = sqlx::query_as(
        r#"
        UPDATE worker_nodes
        SET status = 'revoked', revoked_at = NOW()
        WHERE id = $1
        RETURNING id, name, segment_tag, status, capabilities, max_concurrency, last_heartbeat_at, registered_at, revoked_at
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "revoke failed", auth.request_id, &instance))?;

    let Some(row) = row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Worker node {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let dto = row.into_dto(auth.request_id, &instance)?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "worker.revoked",
            resource_type: "worker_node",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({ "status": "revoked" })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    Ok(Json(dto))
}
