use std::net::IpAddr;

use asi_common::assets::{IgnoredTargetType, TargetType};
use asi_common::error::{DomainError, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use asi_common::scans::{
    ChunkStatus, PreflightRequest, PreflightResponse, ScanChunkDto, ScanRunDto, ScanRunStatus,
    ScanTriggerType, StartScanRequest,
};
use asi_common::worker::{DiscoveryTool, PolicySnapshot, WorkerControlEvent};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use sqlx::{FromRow, PgPool};
use utoipa::IntoParams;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::orchestrator::slicer::{
    compute_preflight, slice_targets, IgnoredEntry, SlicePlan, TargetEntry,
};
use crate::routes::common::{extract_source_ip, map_db_err, require_db};
use crate::routes::policies::ScanPolicyRow;
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(FromRow)]
struct TargetRow {
    target_type: String,
    value: String,
}

#[derive(FromRow)]
struct IgnoredRow {
    target_type: String,
    value: String,
}

#[derive(FromRow)]
pub(crate) struct ScanRunRow {
    pub id: Uuid,
    pub asset_group_id: Uuid,
    pub policy_snapshot: serde_json::Value,
    pub trigger_type: String,
    pub time_slot: Option<String>,
    pub status: String,
    pub total_targets: i32,
    pub total_chunks: i32,
    pub completed_chunks: i32,
    pub ema_chunk_ms: Option<f64>,
    pub estimated_finish_at: Option<DateTime<Utc>>,
    pub started_by: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
}

impl ScanRunRow {
    pub(crate) fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<ScanRunDto, AppError> {
        let trigger_type = ScanTriggerType::from_db_str(&self.trigger_type).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid trigger_type '{}'", self.trigger_type)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        let status = ScanRunStatus::from_db_str(&self.status).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid scan status '{}'", self.status)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        let time_slot = self
            .time_slot
            .as_deref()
            .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok());

        Ok(ScanRunDto {
            id: self.id,
            asset_group_id: self.asset_group_id,
            policy_snapshot: self.policy_snapshot,
            trigger_type,
            time_slot,
            status,
            total_targets: self.total_targets,
            total_chunks: self.total_chunks,
            completed_chunks: self.completed_chunks,
            ema_chunk_ms: self.ema_chunk_ms,
            estimated_finish_at: self.estimated_finish_at,
            started_by: self.started_by,
            started_at: self.started_at,
            finished_at: self.finished_at,
            cancel_requested_at: self.cancel_requested_at,
        })
    }
}

#[derive(FromRow)]
struct ScanChunkRow {
    id: Uuid,
    scan_run_id: Uuid,
    sequence_no: i32,
    subnet_bucket: String,
    targets: serde_json::Value,
    status: String,
    attempt_no: i32,
    leased_by_worker_id: Option<Uuid>,
    lease_expires_at: Option<DateTime<Utc>>,
    duration_ms: Option<i32>,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl ScanChunkRow {
    fn into_dto(self, request_id: Option<Uuid>, instance: &str) -> Result<ScanChunkDto, AppError> {
        let status = ChunkStatus::from_db_str(&self.status).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid chunk status '{}'", self.status)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(ScanChunkDto {
            id: self.id,
            scan_run_id: self.scan_run_id,
            sequence_no: self.sequence_no,
            subnet_bucket: self.subnet_bucket,
            targets: self.targets,
            status,
            attempt_no: self.attempt_no,
            leased_by_worker_id: self.leased_by_worker_id,
            lease_expires_at: self.lease_expires_at,
            duration_ms: self.duration_ms,
            error_message: self.error_message,
            created_at: self.created_at,
            completed_at: self.completed_at,
        })
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct ScanFilterQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub asset_group_id: Option<Uuid>,
}

struct GroupSliceContext {
    policy: ScanPolicyRow,
    plan: SlicePlan,
    force_sv_ips: Vec<IpAddr>,
}

async fn load_group_slice_context(
    pool: &PgPool,
    asset_group_id: Uuid,
    request_id: Option<Uuid>,
    instance: &str,
) -> Result<GroupSliceContext, AppError> {
    let policy: Option<ScanPolicyRow> = sqlx::query_as(
        r#"
        SELECT sp.id, sp.name, sp.port_spec, sp.discovery_tool, sp.rate_pps, sp.per_ip_cooldown_ms,
               sp.subnet_concurrency, sp.kill_grace_seconds, sp.inactivity_threshold,
               sp.tarpit_port_threshold, sp.enable_nuclei, sp.time_windows, sp.created_at, sp.updated_at
        FROM asset_groups ag
        INNER JOIN scan_policies sp ON sp.id = ag.policy_id
        WHERE ag.id = $1
        "#,
    )
    .bind(asset_group_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "asset group lookup failed", request_id, instance))?;

    let Some(policy) = policy else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {asset_group_id} not found.")),
            request_id,
            Some(instance.to_string()),
        ));
    };

    let target_rows: Vec<TargetRow> = sqlx::query_as(
        "SELECT target_type, value FROM asset_group_targets WHERE asset_group_id = $1",
    )
    .bind(asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "targets lookup failed", request_id, instance))?;

    let ignored_rows: Vec<IgnoredRow> = sqlx::query_as(
        "SELECT target_type, value FROM ignored_targets WHERE asset_group_id IS NULL OR asset_group_id = $1",
    )
    .bind(asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "ignored targets lookup failed", request_id, instance))?;

    let force_sv_nets: Vec<IpNetwork> = sqlx::query_scalar(
        "SELECT ip_addr FROM hosts WHERE asset_group_id = $1 AND tarpit_override_force_sv = TRUE",
    )
    .bind(asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "host overrides lookup failed", request_id, instance))?;

    let targets: Vec<TargetEntry> = target_rows
        .into_iter()
        .filter_map(|r| {
            TargetType::from_db_str(&r.target_type).map(|tt| TargetEntry {
                target_type: tt,
                value: r.value,
            })
        })
        .collect();

    let ignored: Vec<IgnoredEntry> = ignored_rows
        .into_iter()
        .filter_map(|r| {
            IgnoredTargetType::from_db_str(&r.target_type).map(|it| IgnoredEntry {
                target_type: it,
                value: r.value,
            })
        })
        .collect();

    let port_spec = policy.port_spec.clone();
    let rate_pps = u32::try_from(policy.rate_pps.max(1)).unwrap_or(500);

    let plan = tokio::task::spawn_blocking(move || {
        slice_targets(&targets, &ignored, &port_spec, rate_pps)
    })
    .await
    .map_err(|err| {
        AppError::new(
            DomainError::Internal(format!("target slicer task failed: {err}")),
            request_id,
            Some(instance.to_string()),
        )
    })?
    .map_err(|msg| {
        AppError::new(
            DomainError::BadRequest(msg),
            request_id,
            Some(instance.to_string()),
        )
    })?;

    Ok(GroupSliceContext {
        policy,
        plan,
        force_sv_ips: force_sv_nets.into_iter().map(|n| n.ip()).collect(),
    })
}

pub(crate) fn emit_scan_status_ui(
    state: &AppState,
    scan_run_id: Uuid,
    previous_status: &str,
    current_status: &str,
    reason: Option<String>,
) {
    let event_id = Uuid::new_v4();
    state.events.emit_ui(
        "scan.status_changed",
        event_id,
        serde_json::json!({
            "event_id": event_id,
            "occurred_at": Utc::now(),
            "scan_run_id": scan_run_id,
            "previous_status": previous_status,
            "current_status": current_status,
            "reason": reason,
        }),
    );
}

#[utoipa::path(
    post,
    path = "/api/v1/scans/preflight",
    tag = "Scans",
    security(("bearer_auth" = [])),
    request_body = PreflightRequest,
    responses(
        (status = 200, description = "Estimated chunk count and scan duration", body = PreflightResponse),
        (status = 404, description = "Asset group not found", body = ProblemDetails)
    )
)]
pub async fn preflight_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(payload): Json<PreflightRequest>,
) -> Result<Json<PreflightResponse>, AppError> {
    let instance = "/api/v1/scans/preflight";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let ctx =
        load_group_slice_context(pool, payload.asset_group_id, auth.request_id, instance).await?;
    let rate_pps = u32::try_from(ctx.policy.rate_pps.max(1)).unwrap_or(500);
    let window_minutes = payload.window_minutes.unwrap_or(120);
    Ok(Json(compute_preflight(
        payload.asset_group_id,
        &ctx.plan,
        rate_pps,
        window_minutes,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/scans",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(ScanFilterQuery),
    responses(
        (status = 200, description = "Paginated scan runs", body = PaginatedResponse<ScanRunDto>)
    )
)]
pub async fn list_scans(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<ScanFilterQuery>,
) -> Result<Json<PaginatedResponse<ScanRunDto>>, AppError> {
    let instance = "/api/v1/scans";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let pg = PaginationQuery {
        page: filter.page,
        per_page: filter.per_page,
        ..Default::default()
    }
    .sanitized();

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_runs WHERE ($1::uuid IS NULL OR asset_group_id = $1)",
    )
    .bind(filter.asset_group_id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "scan count failed", auth.request_id, instance))?;

    let rows: Vec<ScanRunRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
               total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
               started_by, started_at, finished_at, cancel_requested_at
        FROM scan_runs
        WHERE ($1::uuid IS NULL OR asset_group_id = $1)
        ORDER BY started_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "scan query failed", auth.request_id, instance))?;

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

pub(crate) struct EnqueueScanParams<'a> {
    pub state: &'a AppState,
    pub pool: &'a PgPool,
    pub asset_group_id: Uuid,
    pub trigger: ScanTriggerType,
    pub time_slot: Option<asi_common::diff::TimeSlot>,
    pub started_by: Option<Uuid>,
    pub source_ip: Option<IpNetwork>,
    pub request_id: Option<Uuid>,
    pub instance: &'a str,
}

pub(crate) async fn enqueue_scan_run_for_group(
    params: EnqueueScanParams<'_>,
) -> Result<ScanRunDto, AppError> {
    let ctx = load_group_slice_context(
        params.pool,
        params.asset_group_id,
        params.request_id,
        params.instance,
    )
    .await?;

    if ctx.plan.chunks.is_empty() {
        return Err(AppError::new(
            DomainError::BadRequest(
                "Asset group has zero scannable targets after applying exclusions and ignored list."
                    .to_string(),
            ),
            params.request_id,
            Some(params.instance.to_string()),
        ));
    }

    let discovery_tool =
        DiscoveryTool::from_db_str(&ctx.policy.discovery_tool).unwrap_or(DiscoveryTool::Naabu);
    let snapshot = PolicySnapshot {
        port_spec: ctx.policy.port_spec.clone(),
        discovery_tool,
        rate_pps: u32::try_from(ctx.policy.rate_pps.max(1)).unwrap_or(500),
        per_ip_cooldown_ms: u64::try_from(ctx.policy.per_ip_cooldown_ms.max(0)).unwrap_or(250),
        subnet_concurrency: u32::try_from(ctx.policy.subnet_concurrency.max(1)).unwrap_or(4),
        kill_grace_seconds: u64::try_from(ctx.policy.kill_grace_seconds.clamp(1, 10)).unwrap_or(3),
        inactivity_threshold: u32::try_from(ctx.policy.inactivity_threshold.max(1)).unwrap_or(3),
        tarpit_port_threshold: u32::try_from(ctx.policy.tarpit_port_threshold.max(1))
            .unwrap_or(200),
        enable_nuclei: ctx.policy.enable_nuclei,
        force_sv_ips: ctx.force_sv_ips,
    };
    let snapshot_json = serde_json::to_value(&snapshot).map_err(|err| {
        AppError::new(
            DomainError::Internal(format!("failed to serialize policy snapshot: {err}")),
            params.request_id,
            Some(params.instance.to_string()),
        )
    })?;

    let time_slot_str = params.time_slot.map(|ts| ts.as_db_str().to_string());
    let total_targets = i32::try_from(ctx.plan.total_targets).unwrap_or(i32::MAX);
    let total_chunks = i32::try_from(ctx.plan.chunks.len()).unwrap_or(i32::MAX);

    let mut tx =
        params.pool.begin().await.map_err(|err| {
            map_db_err(err, "transaction error", params.request_id, params.instance)
        })?;

    let run_row: ScanRunRow = sqlx::query_as(
        r#"
        INSERT INTO scan_runs (
            asset_group_id, policy_snapshot, trigger_type, time_slot, status,
            total_targets, total_chunks, completed_chunks, started_by
        )
        VALUES ($1, $2, $3, $4, 'queued', $5, $6, 0, $7)
        RETURNING id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
                  total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
                  started_by, started_at, finished_at, cancel_requested_at
        "#,
    )
    .bind(params.asset_group_id)
    .bind(&snapshot_json)
    .bind(params.trigger.as_db_str())
    .bind(time_slot_str)
    .bind(total_targets)
    .bind(total_chunks)
    .bind(params.started_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "failed to create scan run",
            params.request_id,
            params.instance,
        )
    })?;

    for chunk in &ctx.plan.chunks {
        let targets_json = serde_json::to_value(&chunk.targets).map_err(|err| {
            AppError::new(
                DomainError::Internal(format!("failed to serialize chunk targets: {err}")),
                params.request_id,
                Some(params.instance.to_string()),
            )
        })?;
        sqlx::query(
            r#"
            INSERT INTO scan_chunks (scan_run_id, sequence_no, subnet_bucket, targets, status)
            VALUES ($1, $2, $3, $4, 'pending')
            "#,
        )
        .bind(run_row.id)
        .bind(chunk.sequence_no)
        .bind(&chunk.subnet_bucket)
        .bind(&targets_json)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "failed to insert scan chunk",
                params.request_id,
                params.instance,
            )
        })?;
    }

    let actor_type = if params.started_by.is_some() {
        "user"
    } else {
        "system"
    };
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type,
            actor_id: params.started_by,
            action: "scan_run.started",
            resource_type: "scan_run",
            resource_id: Some(run_row.id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "asset_group_id": params.asset_group_id,
                "trigger_type": params.trigger.as_db_str(),
                "total_targets": total_targets,
                "total_chunks": total_chunks,
            })),
            source_ip: params.source_ip,
            request_id: params.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", params.request_id, params.instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", params.request_id, params.instance))?;

    let dto = run_row.into_dto(params.request_id, params.instance)?;
    emit_scan_status_ui(params.state, dto.id, "none", "queued", None);

    Ok(dto)
}

#[utoipa::path(
    post,
    path = "/api/v1/scans",
    tag = "Scans",
    security(("bearer_auth" = [])),
    request_body = StartScanRequest,
    responses(
        (status = 201, description = "Scan queued and micro-chunks generated", body = ScanRunDto),
        (status = 404, description = "Asset group not found", body = ProblemDetails),
        (status = 422, description = "No scannable targets remain", body = ProblemDetails)
    )
)]
pub async fn start_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<StartScanRequest>,
) -> Result<(StatusCode, Json<ScanRunDto>), AppError> {
    let instance = "/api/v1/scans";
    auth.require(Permission::RunOrStopScans, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let dto = enqueue_scan_run_for_group(EnqueueScanParams {
        state: &state,
        pool,
        asset_group_id: payload.asset_group_id,
        trigger: payload.trigger_type.unwrap_or(ScanTriggerType::Manual),
        time_slot: payload.time_slot,
        started_by: Some(auth.user.id),
        source_ip,
        request_id: auth.request_id,
        instance,
    })
    .await?;

    Ok((StatusCode::CREATED, Json(dto)))
}

#[utoipa::path(
    get,
    path = "/api/v1/scans/{id}",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan run UUID")),
    responses(
        (status = 200, description = "Scan run details", body = ScanRunDto),
        (status = 404, description = "Scan run not found", body = ProblemDetails)
    )
)]
pub async fn get_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanRunDto>, AppError> {
    let instance = format!("/api/v1/scans/{id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let row: Option<ScanRunRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
               total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
               started_by, started_at, finished_at, cancel_requested_at
        FROM scan_runs
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "scan lookup failed", auth.request_id, &instance))?;

    let Some(row) = row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Scan run {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    Ok(Json(row.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/scans/{id}/chunks",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan run UUID"), PaginationQuery),
    responses(
        (status = 200, description = "Paginated chunks for a scan run", body = PaginatedResponse<ScanChunkDto>)
    )
)]
pub async fn list_scan_chunks(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<ScanChunkDto>>, AppError> {
    let instance = format!("/api/v1/scans/{id}/chunks");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let pg = query.sanitized();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "chunk count failed", auth.request_id, &instance))?;

    let rows: Vec<ScanChunkRow> = sqlx::query_as(
        r#"
        SELECT id, scan_run_id, sequence_no, subnet_bucket, targets, status, attempt_no,
               leased_by_worker_id, lease_expires_at, duration_ms, error_message, created_at, completed_at
        FROM scan_chunks
        WHERE scan_run_id = $1
        ORDER BY sequence_no ASC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "chunk query failed", auth.request_id, &instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, &instance))
        .collect::<Result<Vec<_>, _>>()?;
    let total_u64 = u64::try_from(total.max(0)).unwrap_or(0);

    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(pg.page, pg.per_page, total_u64),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/scans/{id}/pause",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan run UUID")),
    responses(
        (status = 200, description = "Pause signal issued; active chunks gracefully released", body = ScanRunDto),
        (status = 404, description = "Scan run not found", body = ProblemDetails),
        (status = 409, description = "Scan run cannot be paused in its current state", body = ProblemDetails)
    )
)]
pub async fn pause_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanRunDto>, AppError> {
    let instance = format!("/api/v1/scans/{id}/pause");
    auth.require(Permission::RunOrStopScans, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let current: Option<ScanRunRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
               total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
               started_by, started_at, finished_at, cancel_requested_at
        FROM scan_runs
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    let Some(current) = current else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Scan run {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    if !matches!(current.status.as_str(), "queued" | "running") {
        return Err(AppError::new(
            DomainError::Conflict(format!("Cannot pause scan in status '{}'.", current.status)),
            auth.request_id,
            Some(instance),
        ));
    }

    let leased_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status = 'leased'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "chunk count failed", auth.request_id, &instance))?;

    let next_status = if leased_count > 0 {
        "pausing"
    } else {
        "paused"
    };

    let updated: ScanRunRow = sqlx::query_as(
        r#"
        UPDATE scan_runs
        SET status = $1, cancel_requested_at = NOW()
        WHERE id = $2
        RETURNING id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
                  total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
                  started_by, started_at, finished_at, cancel_requested_at
        "#,
    )
    .bind(next_status)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "pause update failed", auth.request_id, &instance))?;

    let grace_seconds = updated
        .policy_snapshot
        .get("kill_grace_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(3);

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "scan_run.paused",
            resource_type: "scan_run",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({ "status": current.status })),
            after_state: Some(serde_json::json!({ "status": next_status })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    state.events.emit_worker_control(WorkerControlEvent {
        action: "pause_scan_run".to_string(),
        scan_run_id: Some(id),
        chunk_id: None,
        grace_seconds: Some(grace_seconds),
    });
    emit_scan_status_ui(
        &state,
        id,
        &current.status,
        next_status,
        Some("user_requested_pause".to_string()),
    );

    Ok(Json(updated.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/scans/{id}/resume",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan run UUID")),
    responses(
        (status = 200, description = "Paused scan resumed", body = ScanRunDto),
        (status = 404, description = "Scan run not found", body = ProblemDetails),
        (status = 409, description = "Scan run is not paused", body = ProblemDetails)
    )
)]
pub async fn resume_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanRunDto>, AppError> {
    let instance = format!("/api/v1/scans/{id}/resume");
    auth.require(Permission::RunOrStopScans, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let current: Option<ScanRunRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
               total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
               started_by, started_at, finished_at, cancel_requested_at
        FROM scan_runs
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    let Some(current) = current else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Scan run {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    if !matches!(current.status.as_str(), "paused" | "pausing") {
        return Err(AppError::new(
            DomainError::Conflict(format!(
                "Cannot resume scan in status '{}'.",
                current.status
            )),
            auth.request_id,
            Some(instance),
        ));
    }

    let next_status = if current.completed_chunks > 0 {
        "running"
    } else {
        "queued"
    };

    let updated: ScanRunRow = sqlx::query_as(
        r#"
        UPDATE scan_runs
        SET status = $1, cancel_requested_at = NULL
        WHERE id = $2
        RETURNING id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
                  total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
                  started_by, started_at, finished_at, cancel_requested_at
        "#,
    )
    .bind(next_status)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "resume update failed", auth.request_id, &instance))?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "scan_run.resumed",
            resource_type: "scan_run",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({ "status": current.status })),
            after_state: Some(serde_json::json!({ "status": next_status })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    emit_scan_status_ui(&state, id, &current.status, next_status, None);

    Ok(Json(updated.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/scans/{id}/stop",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan run UUID")),
    responses(
        (status = 200, description = "Hard Kill Switch triggered for scan run", body = ScanRunDto),
        (status = 404, description = "Scan run not found", body = ProblemDetails),
        (status = 409, description = "Scan run already finished", body = ProblemDetails)
    )
)]
pub async fn stop_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanRunDto>, AppError> {
    let instance = format!("/api/v1/scans/{id}/stop");
    auth.require(Permission::RunOrStopScans, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let current: Option<ScanRunRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
               total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
               started_by, started_at, finished_at, cancel_requested_at
        FROM scan_runs
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    let Some(current) = current else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Scan run {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    if matches!(current.status.as_str(), "stopped" | "completed" | "failed") {
        return Err(AppError::new(
            DomainError::Conflict(format!(
                "Scan is already in terminal status '{}'.",
                current.status
            )),
            auth.request_id,
            Some(instance),
        ));
    }

    sqlx::query(
        "UPDATE scan_chunks SET status = 'cancelled' WHERE scan_run_id = $1 AND status = 'pending'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "cancel pending chunks failed",
            auth.request_id,
            &instance,
        )
    })?;

    let leased_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_chunks WHERE scan_run_id = $1 AND status = 'leased'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "leased check failed", auth.request_id, &instance))?;

    let (next_status, finished_now) = if leased_count > 0 {
        ("stopping", false)
    } else {
        ("stopped", true)
    };

    let updated: ScanRunRow = sqlx::query_as(
        r#"
        UPDATE scan_runs
        SET status = $1,
            cancel_requested_at = COALESCE(cancel_requested_at, NOW()),
            finished_at = CASE WHEN $2 THEN NOW() ELSE finished_at END
        WHERE id = $3
        RETURNING id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
                  total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
                  started_by, started_at, finished_at, cancel_requested_at
        "#,
    )
    .bind(next_status)
    .bind(finished_now)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "stop update failed", auth.request_id, &instance))?;

    let grace_seconds = updated
        .policy_snapshot
        .get("kill_grace_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(3);

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "scan_run.stopped",
            resource_type: "scan_run",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({ "status": current.status })),
            after_state: Some(serde_json::json!({ "status": next_status })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    state.events.emit_worker_control(WorkerControlEvent {
        action: "stop_scan_run".to_string(),
        scan_run_id: Some(id),
        chunk_id: None,
        grace_seconds: Some(grace_seconds),
    });
    emit_scan_status_ui(
        &state,
        id,
        &current.status,
        next_status,
        Some("hard_kill_switch".to_string()),
    );

    Ok(Json(updated.into_dto(auth.request_id, &instance)?))
}
