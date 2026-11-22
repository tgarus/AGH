use asi_common::assets::{CreateScanPolicyRequest, ScanPolicyDto, UpdateScanPolicyRequest};
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use asi_common::validation::validate_scan_policy_bounds;
use asi_common::worker::DiscoveryTool;
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

#[derive(FromRow)]
pub(crate) struct ScanPolicyRow {
    pub id: Uuid,
    pub name: String,
    pub port_spec: String,
    pub discovery_tool: String,
    pub rate_pps: i32,
    pub per_ip_cooldown_ms: i32,
    pub subnet_concurrency: i32,
    pub kill_grace_seconds: i32,
    pub inactivity_threshold: i32,
    pub tarpit_port_threshold: i32,
    pub enable_nuclei: bool,
    pub time_windows: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScanPolicyRow {
    pub(crate) fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<ScanPolicyDto, AppError> {
        let discovery_tool = DiscoveryTool::from_db_str(&self.discovery_tool).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("unknown discovery_tool '{}'", self.discovery_tool)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(ScanPolicyDto {
            id: self.id,
            name: self.name,
            port_spec: self.port_spec,
            discovery_tool,
            rate_pps: self.rate_pps,
            per_ip_cooldown_ms: self.per_ip_cooldown_ms,
            subnet_concurrency: self.subnet_concurrency,
            kill_grace_seconds: self.kill_grace_seconds,
            inactivity_threshold: self.inactivity_threshold,
            tarpit_port_threshold: self.tarpit_port_threshold,
            enable_nuclei: self.enable_nuclei,
            time_windows: self.time_windows,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/policies",
    tag = "Policies",
    security(("bearer_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated scan policies", body = PaginatedResponse<ScanPolicyDto>)
    )
)]
pub async fn list_policies(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<ScanPolicyDto>>, AppError> {
    let instance = "/api/v1/policies";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let pg = query.sanitized();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_policies")
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "policy count failed", auth.request_id, instance))?;

    let rows: Vec<ScanPolicyRow> = sqlx::query_as(
        r#"
        SELECT id, name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms, subnet_concurrency,
               kill_grace_seconds, inactivity_threshold, tarpit_port_threshold, enable_nuclei, time_windows,
               created_at, updated_at
        FROM scan_policies
        ORDER BY created_at ASC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "policy query failed", auth.request_id, instance))?;

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
    path = "/api/v1/policies",
    tag = "Policies",
    security(("bearer_auth" = [])),
    request_body = CreateScanPolicyRequest,
    responses(
        (status = 201, description = "Scan policy created", body = ScanPolicyDto),
        (status = 409, description = "Policy name already exists", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn create_policy(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateScanPolicyRequest>,
) -> Result<(StatusCode, Json<ScanPolicyDto>), AppError> {
    let instance = "/api/v1/policies";
    auth.require(Permission::ManageGroupPolicies, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let name = payload.name.trim().to_string();
    let kill_grace = payload.kill_grace_seconds.unwrap_or(3);
    let inactivity = payload.inactivity_threshold.unwrap_or(3);
    let tarpit_thresh = payload.tarpit_port_threshold.unwrap_or(200);
    let enable_nuclei = payload.enable_nuclei.unwrap_or(false);
    let time_windows = payload
        .time_windows
        .unwrap_or_else(|| serde_json::json!({}));

    let mut violations = validate_scan_policy_bounds(
        &payload.port_spec,
        payload.rate_pps,
        payload.per_ip_cooldown_ms,
        payload.subnet_concurrency,
        kill_grace,
        inactivity,
        tarpit_thresh,
    );
    if name.is_empty() {
        violations.push(FieldViolation {
            field: "name".to_string(),
            code: "REQUIRED".to_string(),
            message: "Policy name cannot be empty.".to_string(),
        });
    }
    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Scan policy failed validation.".to_string(),
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

    let row: ScanPolicyRow = sqlx::query_as(
        r#"
        INSERT INTO scan_policies (
            name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms, subnet_concurrency,
            kill_grace_seconds, inactivity_threshold, tarpit_port_threshold, enable_nuclei, time_windows
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id, name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms, subnet_concurrency,
                  kill_grace_seconds, inactivity_threshold, tarpit_port_threshold, enable_nuclei, time_windows,
                  created_at, updated_at
        "#,
    )
    .bind(&name)
    .bind(payload.port_spec.trim().to_ascii_lowercase())
    .bind(payload.discovery_tool.as_db_str())
    .bind(payload.rate_pps)
    .bind(payload.per_ip_cooldown_ms)
    .bind(payload.subnet_concurrency)
    .bind(kill_grace)
    .bind(inactivity)
    .bind(tarpit_thresh)
    .bind(enable_nuclei)
    .bind(&time_windows)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "Scan policy with this name already exists.", auth.request_id, instance))?;

    let dto = row.into_dto(auth.request_id, instance)?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "scan_policy.created",
            resource_type: "scan_policy",
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
    patch,
    path = "/api/v1/policies/{id}",
    tag = "Policies",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan policy UUID")),
    request_body = UpdateScanPolicyRequest,
    responses(
        (status = 200, description = "Scan policy updated", body = ScanPolicyDto),
        (status = 404, description = "Policy not found", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn update_policy(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateScanPolicyRequest>,
) -> Result<Json<ScanPolicyDto>, AppError> {
    let instance = format!("/api/v1/policies/{id}");
    auth.require(Permission::ManageGroupPolicies, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let existing: Option<ScanPolicyRow> = sqlx::query_as(
        r#"
        SELECT id, name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms, subnet_concurrency,
               kill_grace_seconds, inactivity_threshold, tarpit_port_threshold, enable_nuclei, time_windows,
               created_at, updated_at
        FROM scan_policies
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    let Some(existing) = existing else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Scan policy {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let before_dto = existing.into_dto(auth.request_id, &instance)?;
    let next_name = payload
        .name
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| before_dto.name.clone());
    let next_port_spec = payload
        .port_spec
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| before_dto.port_spec.clone());
    let next_tool = payload.discovery_tool.unwrap_or(before_dto.discovery_tool);
    let next_rate = payload.rate_pps.unwrap_or(before_dto.rate_pps);
    let next_cooldown = payload
        .per_ip_cooldown_ms
        .unwrap_or(before_dto.per_ip_cooldown_ms);
    let next_concurrency = payload
        .subnet_concurrency
        .unwrap_or(before_dto.subnet_concurrency);
    let next_grace = payload
        .kill_grace_seconds
        .unwrap_or(before_dto.kill_grace_seconds);
    let next_inactivity = payload
        .inactivity_threshold
        .unwrap_or(before_dto.inactivity_threshold);
    let next_tarpit = payload
        .tarpit_port_threshold
        .unwrap_or(before_dto.tarpit_port_threshold);
    let next_nuclei = payload.enable_nuclei.unwrap_or(before_dto.enable_nuclei);
    let next_windows = payload
        .time_windows
        .unwrap_or_else(|| before_dto.time_windows.clone());

    let mut violations = validate_scan_policy_bounds(
        &next_port_spec,
        next_rate,
        next_cooldown,
        next_concurrency,
        next_grace,
        next_inactivity,
        next_tarpit,
    );
    if next_name.is_empty() {
        violations.push(FieldViolation {
            field: "name".to_string(),
            code: "REQUIRED".to_string(),
            message: "Policy name cannot be empty.".to_string(),
        });
    }
    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Scan policy failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance),
        ));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction failed", auth.request_id, &instance))?;

    let row: ScanPolicyRow = sqlx::query_as(
        r#"
        UPDATE scan_policies
        SET name = $1, port_spec = $2, discovery_tool = $3, rate_pps = $4,
            per_ip_cooldown_ms = $5, subnet_concurrency = $6, kill_grace_seconds = $7,
            inactivity_threshold = $8, tarpit_port_threshold = $9, enable_nuclei = $10,
            time_windows = $11, updated_at = NOW()
        WHERE id = $12
        RETURNING id, name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms, subnet_concurrency,
                  kill_grace_seconds, inactivity_threshold, tarpit_port_threshold, enable_nuclei, time_windows,
                  created_at, updated_at
        "#,
    )
    .bind(&next_name)
    .bind(&next_port_spec)
    .bind(next_tool.as_db_str())
    .bind(next_rate)
    .bind(next_cooldown)
    .bind(next_concurrency)
    .bind(next_grace)
    .bind(next_inactivity)
    .bind(next_tarpit)
    .bind(next_nuclei)
    .bind(&next_windows)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "Scan policy name already exists.", auth.request_id, &instance))?;

    let after_dto = row.into_dto(auth.request_id, &instance)?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "scan_policy.updated",
            resource_type: "scan_policy",
            resource_id: Some(id),
            before_state: serde_json::to_value(&before_dto).ok(),
            after_state: serde_json::to_value(&after_dto).ok(),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    Ok(Json(after_dto))
}

#[utoipa::path(
    delete,
    path = "/api/v1/policies/{id}",
    tag = "Policies",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan policy UUID")),
    responses(
        (status = 204, description = "Scan policy deleted"),
        (status = 404, description = "Policy not found", body = ProblemDetails),
        (status = 409, description = "Policy is referenced by an asset group", body = ProblemDetails)
    )
)]
pub async fn delete_policy(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/policies/{id}");
    auth.require(Permission::ManageGroupPolicies, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction failed", auth.request_id, &instance))?;

    let deleted: Option<String> =
        sqlx::query_scalar("DELETE FROM scan_policies WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(
                    err,
                    "Scan policy is still attached to one or more asset groups.",
                    auth.request_id,
                    &instance,
                )
            })?;

    let Some(name) = deleted else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Scan policy {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "scan_policy.deleted",
            resource_type: "scan_policy",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({ "name": name })),
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
