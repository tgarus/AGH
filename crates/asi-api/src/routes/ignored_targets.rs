use asi_common::assets::{CreateIgnoredTargetRequest, IgnoredTargetDto, IgnoredTargetType};
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use asi_common::validation::validate_ignored_target_value;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::FromRow;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::routes::common::{extract_source_ip, map_db_err, require_db};
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(FromRow)]
pub(crate) struct IgnoredTargetRow {
    pub id: Uuid,
    pub asset_group_id: Option<Uuid>,
    pub target_type: String,
    pub value: String,
    pub reason: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl IgnoredTargetRow {
    pub(crate) fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<IgnoredTargetDto, AppError> {
        let target_type = IgnoredTargetType::from_db_str(&self.target_type).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!(
                    "invalid ignored target_type '{}'",
                    self.target_type
                )),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(IgnoredTargetDto {
            id: self.id,
            asset_group_id: self.asset_group_id,
            target_type,
            value: self.value,
            reason: self.reason,
            created_by: self.created_by,
            created_at: self.created_at,
        })
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct IgnoredTargetFilter {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub asset_group_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/ignored-targets",
    tag = "IgnoredTargets",
    security(("bearer_auth" = [])),
    params(IgnoredTargetFilter),
    responses(
        (status = 200, description = "Paginated ignored targets", body = PaginatedResponse<IgnoredTargetDto>)
    )
)]
pub async fn list_ignored_targets(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<IgnoredTargetFilter>,
) -> Result<Json<PaginatedResponse<IgnoredTargetDto>>, AppError> {
    let instance = "/api/v1/ignored-targets";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let pg = PaginationQuery {
        page: filter.page,
        per_page: filter.per_page,
        ..Default::default()
    }
    .sanitized();

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM ignored_targets
        WHERE ($1::uuid IS NULL OR asset_group_id = $1)
        "#,
    )
    .bind(filter.asset_group_id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "count failed", auth.request_id, instance))?;

    let rows: Vec<IgnoredTargetRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, target_type, value, reason, created_by, created_at
        FROM ignored_targets
        WHERE ($1::uuid IS NULL OR asset_group_id = $1)
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(filter.asset_group_id)
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
    path = "/api/v1/ignored-targets",
    tag = "IgnoredTargets",
    security(("bearer_auth" = [])),
    request_body = CreateIgnoredTargetRequest,
    responses(
        (status = 201, description = "Target added to ignored list", body = IgnoredTargetDto),
        (status = 409, description = "Target already ignored in this scope", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn create_ignored_target(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateIgnoredTargetRequest>,
) -> Result<(StatusCode, Json<IgnoredTargetDto>), AppError> {
    let instance = "/api/v1/ignored-targets";
    auth.require(Permission::ManageIgnoredTargets, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut violations = Vec::new();
    let normalized_value =
        match validate_ignored_target_value("value", payload.target_type, &payload.value) {
            Ok(v) => v,
            Err(violation) => {
                violations.push(violation);
                String::new()
            }
        };

    let reason = payload.reason.trim().to_string();
    if reason.is_empty() {
        violations.push(FieldViolation {
            field: "reason".to_string(),
            code: "REQUIRED".to_string(),
            message: "Ignore reason cannot be empty.".to_string(),
        });
    }

    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Ignored target failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, instance))?;

    let row: IgnoredTargetRow = sqlx::query_as(
        r#"
        INSERT INTO ignored_targets (asset_group_id, target_type, value, reason, created_by)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, asset_group_id, target_type, value, reason, created_by, created_at
        "#,
    )
    .bind(payload.asset_group_id)
    .bind(payload.target_type.as_db_str())
    .bind(&normalized_value)
    .bind(&reason)
    .bind(auth.user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "Target is already on the ignored list for this scope.",
            auth.request_id,
            instance,
        )
    })?;

    let dto = row.into_dto(auth.request_id, instance)?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "ignored_target.created",
            resource_type: "ignored_target",
            resource_id: Some(dto.id),
            before_state: None,
            after_state: serde_json::to_value(&dto).ok(),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, instance))?;

    Ok((StatusCode::CREATED, Json(dto)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/ignored-targets/{id}",
    tag = "IgnoredTargets",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Ignored target UUID")),
    responses(
        (status = 204, description = "Removed from ignored list"),
        (status = 404, description = "Ignored target not found", body = ProblemDetails)
    )
)]
pub async fn delete_ignored_target(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/ignored-targets/{id}");
    auth.require(Permission::ManageIgnoredTargets, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let deleted: Option<String> =
        sqlx::query_scalar("DELETE FROM ignored_targets WHERE id = $1 RETURNING value")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "delete failed", auth.request_id, &instance))?;

    let Some(value) = deleted else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Ignored target {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "ignored_target.deleted",
            resource_type: "ignored_target",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({ "value": value })),
            after_state: None,
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    Ok(StatusCode::NO_CONTENT)
}
