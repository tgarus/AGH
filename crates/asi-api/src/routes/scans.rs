use std::net::IpAddr;

use asi_common::assets::{AuditLogDto, IgnoredTargetDto, IgnoredTargetType, TargetType};
use asi_common::diff::{BulletItem, DiffEventKind, DiffSeverity};
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::inventory::DiffEventDto;
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::{Permission, Role};
use asi_common::scans::{
    ChunkStatus, PreflightRequest, PreflightResponse, QuickScanRequest, QuickScanResponse,
    RecurringScanScheduleDto, ScanChunkDetailDto, ScanChunkDto, ScanExplorationDto,
    ScanHostSampleDto, ScanRunDto, ScanRunStatus, ScanTriggerType, StartScanRequest,
    UpdateRecurringScanRequest,
};
use asi_common::validation::{parse_raw_targets_blob, validate_port_spec};
use asi_common::worker::{ChunkTarget, DiscoveryTool, PolicySnapshot, WorkerControlEvent};
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
use crate::routes::common::{ensure_user_group_access, extract_source_ip, map_db_err, require_db};
use crate::routes::policies::ScanPolicyRow;
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(FromRow)]
struct TargetRow {
    target_type: String,
    value: String,
}

#[derive(FromRow)]
struct IgnoredRow {
    id: Uuid,
    asset_group_id: Option<Uuid>,
    target_type: String,
    value: String,
    reason: String,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
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
    pub include_all_ignored: bool,
    pub overridden_ignored_values: Vec<String>,
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
            include_all_ignored: self.include_all_ignored,
            overridden_ignored_values: self.overridden_ignored_values,
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
    applicable_ignored: Vec<IgnoredTargetDto>,
    overridden_ignored_values: Vec<String>,
}

async fn load_group_slice_context(
    pool: &PgPool,
    asset_group_id: Uuid,
    include_ignored_ids: &[Uuid],
    include_all_ignored: bool,
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
        "SELECT id, asset_group_id, target_type, value, reason, created_by, created_at FROM ignored_targets WHERE asset_group_id IS NULL OR asset_group_id = $1 ORDER BY created_at DESC",
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

    let mut applicable_ignored = Vec::new();
    let mut overridden_ignored_values = Vec::new();
    let mut ignored = Vec::new();

    for r in ignored_rows {
        let Some(it) = IgnoredTargetType::from_db_str(&r.target_type) else {
            continue;
        };
        let is_overridden = include_all_ignored || include_ignored_ids.contains(&r.id);
        applicable_ignored.push(IgnoredTargetDto {
            id: r.id,
            asset_group_id: r.asset_group_id,
            target_type: it,
            value: r.value.clone(),
            reason: r.reason,
            created_by: r.created_by,
            created_at: r.created_at,
        });
        if is_overridden {
            overridden_ignored_values.push(r.value);
        } else {
            ignored.push(IgnoredEntry {
                target_type: it,
                value: r.value,
            });
        }
    }

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
        applicable_ignored,
        overridden_ignored_values,
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
    ensure_user_group_access(pool, &auth, payload.asset_group_id, instance).await?;

    let ctx = load_group_slice_context(
        pool,
        payload.asset_group_id,
        &payload.include_ignored_ids,
        payload.include_all_ignored,
        auth.request_id,
        instance,
    )
    .await?;
    let rate_pps = u32::try_from(ctx.policy.rate_pps.max(1)).unwrap_or(500);
    let window_minutes = payload.window_minutes.unwrap_or(120);
    let mut resp = compute_preflight(payload.asset_group_id, &ctx.plan, rate_pps, window_minutes);
    resp.matched_ignored_targets = ctx.applicable_ignored;
    resp.overridden_ignored_count = ctx.overridden_ignored_values.len();
    Ok(Json(resp))
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
    let is_admin = auth.user.role == Role::Admin;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM scan_runs sr
        WHERE ($1::uuid IS NULL OR sr.asset_group_id = $1)
          AND (
              $2::bool
              OR NOT EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = sr.asset_group_id)
              OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = sr.asset_group_id AND m.user_id = $3)
          )
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(is_admin)
    .bind(auth.user.id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "scan count failed", auth.request_id, instance))?;

    let rows: Vec<ScanRunRow> = sqlx::query_as(
        r#"
        SELECT sr.id, sr.asset_group_id, sr.policy_snapshot, sr.trigger_type, sr.time_slot, sr.status,
               sr.total_targets, sr.total_chunks, sr.completed_chunks, sr.ema_chunk_ms, sr.estimated_finish_at,
               sr.started_by, sr.started_at, sr.finished_at, sr.cancel_requested_at,
               sr.include_all_ignored, sr.overridden_ignored_values
        FROM scan_runs sr
        WHERE ($1::uuid IS NULL OR sr.asset_group_id = $1)
          AND (
              $2::bool
              OR NOT EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = sr.asset_group_id)
              OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = sr.asset_group_id AND m.user_id = $3)
          )
        ORDER BY sr.started_at DESC
        LIMIT $4 OFFSET $5
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(is_admin)
    .bind(auth.user.id)
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
    pub include_ignored_ids: Vec<Uuid>,
    pub include_all_ignored: bool,
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
        &params.include_ignored_ids,
        params.include_all_ignored,
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
            total_targets, total_chunks, completed_chunks, started_by,
            include_all_ignored, overridden_ignored_values
        )
        VALUES ($1, $2, $3, $4, 'queued', $5, $6, 0, $7, $8, $9)
        RETURNING id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
                  total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
                  started_by, started_at, finished_at, cancel_requested_at,
                  include_all_ignored, overridden_ignored_values
        "#,
    )
    .bind(params.asset_group_id)
    .bind(&snapshot_json)
    .bind(params.trigger.as_db_str())
    .bind(time_slot_str)
    .bind(total_targets)
    .bind(total_chunks)
    .bind(params.started_by)
    .bind(params.include_all_ignored)
    .bind(&ctx.overridden_ignored_values)
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

    let _ = crate::notifications::worker::enqueue_webhook_event(
        params.pool,
        Some(params.asset_group_id),
        "scan.started",
        serde_json::json!({
            "scan_run_id": dto.id,
            "asset_group_id": params.asset_group_id,
            "trigger_type": params.trigger.as_db_str(),
            "total_targets": total_targets,
            "total_chunks": total_chunks,
        }),
    )
    .await;

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
    ensure_user_group_access(pool, &auth, payload.asset_group_id, instance).await?;
    let source_ip = extract_source_ip(&headers);

    let recurring_params = if payload.recurring_enabled {
        let interval_value = payload.interval_value.unwrap_or(6);
        let interval_unit = payload
            .interval_unit
            .as_deref()
            .unwrap_or("hours")
            .trim()
            .to_ascii_lowercase();
        let first_run_time = payload
            .first_run_time
            .as_deref()
            .unwrap_or("02:00")
            .trim()
            .to_string();
        let window_minutes = payload.window_minutes.unwrap_or(120);
        let next_run_at = compute_next_recurring_run_at(
            Utc::now(),
            interval_value,
            &interval_unit,
            &first_run_time,
            window_minutes,
        )
        .map_err(|violations| {
            AppError::new(
                DomainError::Validation {
                    detail: "Recurring scan schedule validation failed.".to_string(),
                    violations,
                },
                auth.request_id,
                Some(instance.to_string()),
            )
        })?;
        Some((
            interval_value,
            interval_unit,
            first_run_time,
            window_minutes,
            next_run_at,
        ))
    } else {
        None
    };

    let include_ignored_ids = payload.include_ignored_ids.clone();
    let include_all_ignored = payload.include_all_ignored;

    let dto = enqueue_scan_run_for_group(EnqueueScanParams {
        state: &state,
        pool,
        asset_group_id: payload.asset_group_id,
        trigger: payload.trigger_type.unwrap_or(ScanTriggerType::Manual),
        time_slot: payload.time_slot,
        started_by: Some(auth.user.id),
        include_ignored_ids: payload.include_ignored_ids,
        include_all_ignored: payload.include_all_ignored,
        source_ip,
        request_id: auth.request_id,
        instance,
    })
    .await?;

    if let Some((interval_value, interval_unit, first_run_time, window_minutes, next_run_at)) =
        recurring_params
    {
        let schedule_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO recurring_scan_schedules (
                asset_group_id, interval_value, interval_unit, first_run_time, window_minutes,
                include_all_ignored, include_ignored_ids, last_run_at, last_scan_run_id,
                next_run_at, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
            "#,
        )
        .bind(payload.asset_group_id)
        .bind(interval_value)
        .bind(&interval_unit)
        .bind(&first_run_time)
        .bind(window_minutes)
        .bind(include_all_ignored)
        .bind(&include_ignored_ids)
        .bind(dto.started_at)
        .bind(dto.id)
        .bind(next_run_at)
        .bind(auth.user.id)
        .fetch_one(pool)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "recurring schedule insert failed",
                auth.request_id,
                instance,
            )
        })?;

        let _ = insert_audit_log(
            pool,
            AuditRecord {
                actor_type: "user",
                actor_id: Some(auth.user.id),
                action: "recurring_scan.created",
                resource_type: "recurring_scan_schedule",
                resource_id: Some(schedule_id),
                before_state: None,
                after_state: Some(serde_json::json!({
                    "asset_group_id": payload.asset_group_id,
                    "interval_value": interval_value,
                    "interval_unit": interval_unit,
                    "first_run_time": first_run_time,
                    "window_minutes": window_minutes,
                    "next_run_at": next_run_at,
                })),
                source_ip,
                request_id: auth.request_id,
            },
        )
        .await;
    }

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
               started_by, started_at, finished_at, cancel_requested_at,
               include_all_ignored, overridden_ignored_values
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
               started_by, started_at, finished_at, cancel_requested_at,
               include_all_ignored, overridden_ignored_values
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
                  started_by, started_at, finished_at, cancel_requested_at,
                  include_all_ignored, overridden_ignored_values
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
               started_by, started_at, finished_at, cancel_requested_at,
               include_all_ignored, overridden_ignored_values
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
                  started_by, started_at, finished_at, cancel_requested_at,
                  include_all_ignored, overridden_ignored_values
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
               started_by, started_at, finished_at, cancel_requested_at,
               include_all_ignored, overridden_ignored_values
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
                  started_by, started_at, finished_at, cancel_requested_at,
                  include_all_ignored, overridden_ignored_values
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

#[utoipa::path(
    post,
    path = "/api/v1/scans/quick",
    tag = "Scans",
    security(("bearer_auth" = [])),
    request_body = QuickScanRequest,
    responses(
        (status = 201, description = "Targets auto-detected, added to group, and scan started immediately", body = QuickScanResponse),
        (status = 403, description = "Requires RunOrStopScans and ManageAssetGroups permissions", body = ProblemDetails),
        (status = 422, description = "Invalid targets or policy parameters", body = ProblemDetails)
    )
)]
pub async fn quick_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<QuickScanRequest>,
) -> Result<(StatusCode, Json<QuickScanResponse>), AppError> {
    let instance = "/api/v1/scans/quick";
    auth.require(Permission::RunOrStopScans, instance)?;
    auth.require(Permission::ManageAssetGroups, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    if let Some(gid) = payload.asset_group_id {
        ensure_user_group_access(pool, &auth, gid, instance).await?;
    }
    let source_ip = extract_source_ip(&headers);

    let targets = parse_raw_targets_blob(&payload.targets_raw).map_err(|violations| {
        AppError::new(
            DomainError::Validation {
                detail: "Quick scan targets failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        )
    })?;

    if let Some(ref ps) = payload.port_spec {
        if let Err(msg) = validate_port_spec(ps) {
            return Err(AppError::new(
                DomainError::Validation {
                    detail: "Quick scan policy validation failed.".to_string(),
                    violations: vec![FieldViolation {
                        field: "port_spec".to_string(),
                        code: "INVALID_PORT_SPEC".to_string(),
                        message: msg,
                    }],
                },
                auth.request_id,
                Some(instance.to_string()),
            ));
        }
    }
    if let Some(rate) = payload.rate_pps {
        if rate <= 0 {
            return Err(AppError::new(
                DomainError::Validation {
                    detail: "Quick scan policy validation failed.".to_string(),
                    violations: vec![FieldViolation {
                        field: "rate_pps".to_string(),
                        code: "OUT_OF_RANGE".to_string(),
                        message: "rate_pps must be > 0.".to_string(),
                    }],
                },
                auth.request_id,
                Some(instance.to_string()),
            ));
        }
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, instance))?;

    let (group_id, group_name): (Uuid, String) = if let Some(gid) = payload.asset_group_id {
        let existing: Option<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM asset_groups WHERE id = $1")
                .bind(gid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|err| map_db_err(err, "group lookup failed", auth.request_id, instance))?;
        let Some((id, name)) = existing else {
            return Err(AppError::new(
                DomainError::NotFound(format!("Asset group {gid} not found.")),
                auth.request_id,
                Some(instance.to_string()),
            ));
        };
        (id, name)
    } else {
        let desired_name = payload
            .group_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("Quick Scan {}", Utc::now().format("%Y-%m-%d %H:%M:%S")));

        let existing: Option<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM asset_groups WHERE name = $1")
                .bind(&desired_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|err| map_db_err(err, "group lookup failed", auth.request_id, instance))?;

        if let Some((id, name)) = existing {
            (id, name)
        } else {
            let policy_id: Uuid = if payload.port_spec.is_some() || payload.rate_pps.is_some() {
                let port_spec = payload
                    .port_spec
                    .as_deref()
                    .map(|s| s.trim().to_ascii_lowercase())
                    .unwrap_or_else(|| "top-1000".to_string());
                let rate_pps = payload.rate_pps.unwrap_or(500);
                let pol_name = format!("quick-{}", &Uuid::new_v4().to_string()[..8]);
                sqlx::query_scalar(
                    r#"
                        INSERT INTO scan_policies (
                            name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms,
                            subnet_concurrency, kill_grace_seconds, inactivity_threshold,
                            tarpit_port_threshold, enable_nuclei, time_windows
                        )
                        VALUES ($1, $2, 'naabu', $3, 250, 4, 3, 3, 200, FALSE, '{}'::jsonb)
                        RETURNING id
                        "#,
                )
                .bind(&pol_name)
                .bind(&port_spec)
                .bind(rate_pps)
                .fetch_one(&mut *tx)
                .await
                .map_err(|err| {
                    map_db_err(err, "quick policy insert failed", auth.request_id, instance)
                })?
            } else if let Some(pid) = sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM scan_policies ORDER BY created_at ASC LIMIT 1",
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "policy lookup failed", auth.request_id, instance))?
            {
                pid
            } else {
                sqlx::query_scalar(
                        r#"
                        INSERT INTO scan_policies (
                            name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms,
                            subnet_concurrency, kill_grace_seconds, inactivity_threshold,
                            tarpit_port_threshold, enable_nuclei, time_windows
                        )
                        VALUES ('default-quick', 'top-1000', 'naabu', 500, 250, 4, 3, 3, 200, FALSE, '{}'::jsonb)
                        RETURNING id
                        "#,
                    )
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|err| {
                        map_db_err(err, "default policy insert failed", auth.request_id, instance)
                    })?
            };

            let created_id: Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO asset_groups (name, description, policy_id, sampling_enabled, created_by)
                VALUES ($1, 'Quick Scan auto-created group', $2, FALSE, $3)
                RETURNING id
                "#,
            )
            .bind(&desired_name)
            .bind(policy_id)
            .bind(auth.user.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "quick group insert failed", auth.request_id, instance)
            })?;
            (created_id, desired_name)
        }
    };

    let mut inserted_count = 0usize;
    for t in &targets {
        let res = sqlx::query(
            r#"
            INSERT INTO asset_group_targets (asset_group_id, target_type, value, notes)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (asset_group_id, target_type, value) DO NOTHING
            "#,
        )
        .bind(group_id)
        .bind(t.target_type.as_db_str())
        .bind(&t.value)
        .bind(&t.notes)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "quick target insert failed", auth.request_id, instance))?;
        if res.rows_affected() > 0 {
            inserted_count += 1;
        }
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "scan_run.quick_scan",
            resource_type: "asset_group",
            resource_id: Some(group_id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "group_name": group_name,
                "received_targets": targets.len(),
                "inserted_targets": inserted_count,
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

    let scan_run = enqueue_scan_run_for_group(EnqueueScanParams {
        state: &state,
        pool,
        asset_group_id: group_id,
        trigger: ScanTriggerType::Manual,
        time_slot: None,
        started_by: Some(auth.user.id),
        include_ignored_ids: payload.include_ignored_ids,
        include_all_ignored: payload.include_all_ignored,
        source_ip,
        request_id: auth.request_id,
        instance,
    })
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(QuickScanResponse {
            asset_group_id: group_id,
            asset_group_name: group_name,
            imported_targets: inserted_count,
            scan_run,
        }),
    ))
}

#[derive(FromRow)]
struct ExploreChunkRow {
    id: Uuid,
    sequence_no: i32,
    subnet_bucket: String,
    targets: serde_json::Value,
    status: String,
    attempt_no: i32,
    leased_by_worker_id: Option<Uuid>,
    leased_by_worker_name: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    duration_ms: Option<i32>,
    error_message: Option<String>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

#[derive(FromRow)]
struct ExploreDiffRow {
    id: Uuid,
    host_id: Uuid,
    asset_group_id: Uuid,
    ip_addr: IpNetwork,
    scan_run_id: Option<Uuid>,
    event_kind: String,
    severity: String,
    bullet_items: serde_json::Value,
    previous_snapshot: Option<serde_json::Value>,
    current_snapshot: Option<serde_json::Value>,
    acknowledged_by: Option<Uuid>,
    acknowledged_at: Option<DateTime<Utc>>,
    detected_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ExploreSampleRow {
    host_id: Uuid,
    ip_addr: IpNetwork,
    status: String,
    is_alive: bool,
    time_slot: String,
    open_ports_hash: String,
    sampled_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ExploreDiffHistoryRow {
    host_id: Uuid,
    scan_run_id: Option<Uuid>,
    previous_snapshot: Option<serde_json::Value>,
    current_snapshot: Option<serde_json::Value>,
    detected_at: DateTime<Utc>,
}

fn extract_ports_from_snapshot(snap: &Option<serde_json::Value>) -> Option<Vec<i32>> {
    let ports_arr = snap.as_ref()?.get("ports")?.as_array()?;
    let mut ports: Vec<i32> = ports_arr
        .iter()
        .filter_map(|p| {
            let state = p.get("state").and_then(|s| s.as_str());
            if state == Some("closed") {
                return None;
            }
            p.get("port")
                .and_then(|v| v.as_i64())
                .and_then(|v| i32::try_from(v).ok())
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    Some(ports)
}

fn resolve_sample_ports_for_scan(
    scan_id: Uuid,
    sample_time: DateTime<Utc>,
    history: &[ExploreDiffHistoryRow],
    fallback_ports: Vec<i32>,
) -> Vec<i32> {
    if let Some(ports) = history
        .iter()
        .rev()
        .filter(|d| d.scan_run_id == Some(scan_id))
        .find_map(|d| extract_ports_from_snapshot(&d.current_snapshot))
    {
        return ports;
    }

    if let Some(ports) = history
        .iter()
        .filter(|d| d.scan_run_id != Some(scan_id) && d.detected_at > sample_time)
        .find_map(|d| extract_ports_from_snapshot(&d.previous_snapshot))
    {
        return ports;
    }

    if let Some(ports) = history
        .iter()
        .rev()
        .filter(|d| d.detected_at <= sample_time)
        .find_map(|d| extract_ports_from_snapshot(&d.current_snapshot))
    {
        return ports;
    }

    fallback_ports
}

#[derive(FromRow)]
struct ExploreAuditRow {
    id: Uuid,
    actor_type: String,
    actor_id: Option<Uuid>,
    action: String,
    resource_type: String,
    resource_id: Option<Uuid>,
    before_state: Option<serde_json::Value>,
    after_state: Option<serde_json::Value>,
    source_ip: Option<IpNetwork>,
    request_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/api/v1/scans/{id}/explore",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Scan run UUID")),
    responses(
        (status = 200, description = "Deep exploration report for a scan run (chunks, workers, diffs, host samples, and audit trail)", body = ScanExplorationDto),
        (status = 404, description = "Scan run not found", body = ProblemDetails)
    )
)]
pub async fn explore_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScanExplorationDto>, AppError> {
    let instance = format!("/api/v1/scans/{id}/explore");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let scan_row: Option<ScanRunRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, policy_snapshot, trigger_type, time_slot, status,
               total_targets, total_chunks, completed_chunks, ema_chunk_ms, estimated_finish_at,
               started_by, started_at, finished_at, cancel_requested_at,
               include_all_ignored, overridden_ignored_values
        FROM scan_runs
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "scan lookup failed", auth.request_id, &instance))?;

    let Some(scan_row) = scan_row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Scan run {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let scan = scan_row.into_dto(auth.request_id, &instance)?;
    ensure_user_group_access(pool, &auth, scan.asset_group_id, &instance).await?;

    let asset_group_name: String =
        sqlx::query_scalar("SELECT name FROM asset_groups WHERE id = $1")
            .bind(scan.asset_group_id)
            .fetch_optional(pool)
            .await
            .map_err(|err| map_db_err(err, "group name lookup failed", auth.request_id, &instance))?
            .unwrap_or_else(|| scan.asset_group_id.to_string());

    let chunk_rows: Vec<ExploreChunkRow> = sqlx::query_as(
        r#"
        SELECT sc.id, sc.sequence_no, sc.subnet_bucket, sc.targets, sc.status, sc.attempt_no,
               sc.leased_by_worker_id, wn.name AS leased_by_worker_name,
               sc.lease_expires_at, sc.duration_ms, sc.error_message, sc.created_at, sc.completed_at
        FROM scan_chunks sc
        LEFT JOIN worker_nodes wn ON wn.id = sc.leased_by_worker_id
        WHERE sc.scan_run_id = $1
        ORDER BY sc.sequence_no ASC
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "explore chunks failed", auth.request_id, &instance))?;

    let chunks = chunk_rows
        .into_iter()
        .map(|c| {
            let status = ChunkStatus::from_db_str(&c.status).unwrap_or(ChunkStatus::Pending);
            let target_ips: Vec<String> =
                if let Ok(parsed) = serde_json::from_value::<Vec<ChunkTarget>>(c.targets.clone()) {
                    parsed.into_iter().map(|t| t.ip_addr.to_string()).collect()
                } else if let Some(arr) = c.targets.as_array() {
                    arr.iter()
                        .filter_map(|v| {
                            v.as_str().map(ToString::to_string).or_else(|| {
                                v.get("ip_addr")
                                    .and_then(|ip| ip.as_str())
                                    .map(ToString::to_string)
                            })
                        })
                        .collect()
                } else {
                    Vec::new()
                };
            ScanChunkDetailDto {
                id: c.id,
                sequence_no: c.sequence_no,
                subnet_bucket: c.subnet_bucket,
                target_ips,
                status,
                attempt_no: c.attempt_no,
                leased_by_worker_id: c.leased_by_worker_id,
                leased_by_worker_name: c.leased_by_worker_name,
                lease_expires_at: c.lease_expires_at,
                duration_ms: c.duration_ms,
                error_message: c.error_message,
                created_at: c.created_at,
                completed_at: c.completed_at,
            }
        })
        .collect();

    let diff_rows: Vec<ExploreDiffRow> = sqlx::query_as(
        r#"
        SELECT de.id, de.host_id, h.asset_group_id, h.ip_addr, de.scan_run_id,
               de.event_kind, de.severity, de.bullet_items,
               de.previous_snapshot, de.current_snapshot,
               de.acknowledged_by, de.acknowledged_at, de.detected_at
        FROM diff_events de
        INNER JOIN hosts h ON h.id = de.host_id
        WHERE de.scan_run_id = $1
        ORDER BY de.detected_at DESC
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "explore diffs failed", auth.request_id, &instance))?;

    let mut diffs = Vec::with_capacity(diff_rows.len());
    for r in diff_rows {
        let Some(event_kind) = DiffEventKind::from_db_str(&r.event_kind) else {
            continue;
        };
        let Some(severity) = DiffSeverity::from_db_str(&r.severity) else {
            continue;
        };
        let bullet_items: Vec<BulletItem> =
            serde_json::from_value(r.bullet_items).unwrap_or_default();
        diffs.push(DiffEventDto {
            id: r.id,
            host_id: r.host_id,
            asset_group_id: r.asset_group_id,
            ip_addr: r.ip_addr.ip(),
            scan_run_id: r.scan_run_id,
            event_kind,
            severity,
            bullet_items,
            previous_snapshot: r.previous_snapshot,
            current_snapshot: r.current_snapshot,
            acknowledged_by: r.acknowledged_by,
            acknowledged_at: r.acknowledged_at,
            detected_at: r.detected_at,
        });
    }

    let sample_rows: Vec<ExploreSampleRow> = sqlx::query_as(
        r#"
        SELECT has.host_id, h.ip_addr, h.status, has.is_alive, has.time_slot,
               has.open_ports_hash, has.sampled_at
        FROM host_availability_samples has
        INNER JOIN hosts h ON h.id = has.host_id
        WHERE has.scan_run_id = $1
        ORDER BY h.ip_addr ASC
        LIMIT 500
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "explore samples failed", auth.request_id, &instance))?;

    let host_ids: Vec<Uuid> = sample_rows.iter().map(|s| s.host_id).collect();
    let mut ports_by_host: std::collections::HashMap<Uuid, Vec<i32>> =
        std::collections::HashMap::new();
    let mut diff_history_by_host: std::collections::HashMap<Uuid, Vec<ExploreDiffHistoryRow>> =
        std::collections::HashMap::new();
    if !host_ids.is_empty() {
        let port_rows: Vec<(Uuid, i32)> = sqlx::query_as(
            "SELECT host_id, port FROM host_ports WHERE host_id = ANY($1) AND state = 'active' ORDER BY port ASC",
        )
        .bind(&host_ids)
        .fetch_all(pool)
        .await
        .map_err(|err| map_db_err(err, "explore host ports failed", auth.request_id, &instance))?;
        for (hid, port) in port_rows {
            ports_by_host.entry(hid).or_default().push(port);
        }

        let hist_rows: Vec<ExploreDiffHistoryRow> = sqlx::query_as(
            r#"
            SELECT host_id, scan_run_id, previous_snapshot, current_snapshot, detected_at
            FROM diff_events
            WHERE host_id = ANY($1)
            ORDER BY detected_at ASC
            "#,
        )
        .bind(&host_ids)
        .fetch_all(pool)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "explore diff history failed",
                auth.request_id,
                &instance,
            )
        })?;
        for hrow in hist_rows {
            diff_history_by_host
                .entry(hrow.host_id)
                .or_default()
                .push(hrow);
        }
    }

    let host_samples = sample_rows
        .into_iter()
        .map(|s| {
            let open_ports = if !s.is_alive {
                Vec::new()
            } else {
                let history = diff_history_by_host
                    .get(&s.host_id)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                resolve_sample_ports_for_scan(
                    id,
                    s.sampled_at,
                    history,
                    ports_by_host.remove(&s.host_id).unwrap_or_default(),
                )
            };
            ScanHostSampleDto {
                host_id: s.host_id,
                ip_address: s.ip_addr.ip().to_string(),
                status: s.status,
                is_alive: s.is_alive,
                time_slot: s.time_slot,
                open_ports_hash: s.open_ports_hash,
                sampled_at: s.sampled_at,
                open_ports,
            }
        })
        .collect();

    let audit_rows: Vec<ExploreAuditRow> = sqlx::query_as(
        r#"
        SELECT id, actor_type, actor_id, action, resource_type, resource_id,
               before_state, after_state, source_ip, request_id, created_at
        FROM audit_logs
        WHERE (resource_type = 'scan_run' AND resource_id = $1)
           OR (after_state->>'scan_run_id' = $1::text)
        ORDER BY created_at ASC
        LIMIT 200
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "explore audit failed", auth.request_id, &instance))?;

    let audit_logs = audit_rows
        .into_iter()
        .map(|a| AuditLogDto {
            id: a.id,
            actor_type: a.actor_type,
            actor_id: a.actor_id,
            action: a.action,
            resource_type: a.resource_type,
            resource_id: a.resource_id,
            before_state: a.before_state,
            after_state: a.after_state,
            source_ip: a.source_ip.map(|ip| ip.ip().to_string()),
            request_id: a.request_id,
            created_at: a.created_at,
        })
        .collect();

    Ok(Json(ScanExplorationDto {
        scan,
        asset_group_name,
        chunks,
        diffs,
        host_samples,
        audit_logs,
    }))
}

#[derive(FromRow)]
struct RecurringScanRow {
    id: Uuid,
    asset_group_id: Uuid,
    asset_group_name: String,
    interval_value: i32,
    interval_unit: String,
    first_run_time: String,
    window_minutes: i32,
    include_all_ignored: bool,
    include_ignored_ids: Vec<Uuid>,
    last_run_at: Option<DateTime<Utc>>,
    last_scan_run_id: Option<Uuid>,
    next_run_at: DateTime<Utc>,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<RecurringScanRow> for RecurringScanScheduleDto {
    fn from(r: RecurringScanRow) -> Self {
        Self {
            id: r.id,
            asset_group_id: r.asset_group_id,
            asset_group_name: r.asset_group_name,
            interval_value: r.interval_value,
            interval_unit: r.interval_unit,
            first_run_time: r.first_run_time,
            window_minutes: r.window_minutes,
            include_all_ignored: r.include_all_ignored,
            include_ignored_ids: r.include_ignored_ids,
            last_run_at: r.last_run_at,
            last_scan_run_id: r.last_scan_run_id,
            next_run_at: r.next_run_at,
            created_by: r.created_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

pub(crate) fn compute_next_recurring_run_at(
    now_utc: DateTime<Utc>,
    interval_value: i32,
    interval_unit: &str,
    first_run_time: &str,
    window_minutes: i32,
) -> Result<DateTime<Utc>, Vec<FieldViolation>> {
    let mut violations = Vec::new();
    if !(1..=10_080).contains(&interval_value) {
        violations.push(FieldViolation {
            field: "interval_value".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "interval_value must be between 1 and 10080.".to_string(),
        });
    }
    if !matches!(interval_unit, "minutes" | "hours") {
        violations.push(FieldViolation {
            field: "interval_unit".to_string(),
            code: "INVALID_VALUE".to_string(),
            message: "interval_unit must be 'minutes' or 'hours'.".to_string(),
        });
    }
    if !(5..=1440).contains(&window_minutes) {
        violations.push(FieldViolation {
            field: "window_minutes".to_string(),
            code: "OUT_OF_RANGE".to_string(),
            message: "window_minutes must be between 5 and 1440.".to_string(),
        });
    }

    let parsed_time = first_run_time.trim().split_once(':').and_then(|(hs, ms)| {
        let h: u32 = hs.parse().ok()?;
        let m: u32 = ms.parse().ok()?;
        if h < 24 && m < 60 {
            Some((h, m))
        } else {
            None
        }
    });
    if parsed_time.is_none() {
        violations.push(FieldViolation {
            field: "first_run_time".to_string(),
            code: "INVALID_FORMAT".to_string(),
            message: "first_run_time must be in HH:MM format (00:00 - 23:59).".to_string(),
        });
    }

    if !violations.is_empty() {
        return Err(violations);
    }

    let (hour, minute) = parsed_time.unwrap_or((0, 0));
    let step_minutes = if interval_unit == "hours" {
        i64::from(interval_value).saturating_mul(60)
    } else {
        i64::from(interval_value)
    }
    .max(1);

    let offset_hours = i64::from(crate::orchestrator::scheduler::warsaw_utc_offset_hours(
        now_utc,
    ));
    let local_now = now_utc + chrono::Duration::hours(offset_hours);
    let anchor_local = local_now
        .date_naive()
        .and_hms_opt(hour, minute, 0)
        .unwrap_or_else(|| local_now.naive_utc());
    let mut candidate_utc = anchor_local.and_utc() - chrono::Duration::hours(offset_hours);
    while candidate_utc <= now_utc {
        candidate_utc += chrono::Duration::minutes(step_minutes);
    }
    Ok(candidate_utc)
}

#[utoipa::path(
    get,
    path = "/api/v1/scans/recurring",
    tag = "Scans",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Active recurring group scan schedules", body = Vec<RecurringScanScheduleDto>)
    )
)]
pub async fn list_recurring_scans(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<RecurringScanScheduleDto>>, AppError> {
    let instance = "/api/v1/scans/recurring";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let is_admin = auth.user.role == Role::Admin;

    let rows: Vec<RecurringScanRow> = sqlx::query_as(
        r#"
        SELECT r.id, r.asset_group_id, ag.name AS asset_group_name,
               r.interval_value, r.interval_unit, r.first_run_time, r.window_minutes,
               r.include_all_ignored, r.include_ignored_ids,
               r.last_run_at, r.last_scan_run_id, r.next_run_at,
               r.created_by, r.created_at, r.updated_at
        FROM recurring_scan_schedules r
        INNER JOIN asset_groups ag ON ag.id = r.asset_group_id
        WHERE $1::bool
           OR NOT EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = r.asset_group_id)
           OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = r.asset_group_id AND m.user_id = $2)
        ORDER BY r.next_run_at ASC, r.created_at DESC
        "#,
    )
    .bind(is_admin)
    .bind(auth.user.id)
    .fetch_all(pool)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "recurring scans query failed",
            auth.request_id,
            instance,
        )
    })?;

    Ok(Json(
        rows.into_iter()
            .map(RecurringScanScheduleDto::from)
            .collect(),
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/scans/recurring/{id}",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Recurring scan schedule UUID")),
    request_body = UpdateRecurringScanRequest,
    responses(
        (status = 200, description = "Recurring schedule updated", body = RecurringScanScheduleDto),
        (status = 404, description = "Schedule not found", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn update_recurring_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateRecurringScanRequest>,
) -> Result<Json<RecurringScanScheduleDto>, AppError> {
    let instance = format!("/api/v1/scans/recurring/{id}");
    auth.require(Permission::RunOrStopScans, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let existing: Option<RecurringScanRow> = sqlx::query_as(
        r#"
        SELECT r.id, r.asset_group_id, ag.name AS asset_group_name,
               r.interval_value, r.interval_unit, r.first_run_time, r.window_minutes,
               r.include_all_ignored, r.include_ignored_ids,
               r.last_run_at, r.last_scan_run_id, r.next_run_at,
               r.created_by, r.created_at, r.updated_at
        FROM recurring_scan_schedules r
        INNER JOIN asset_groups ag ON ag.id = r.asset_group_id
        WHERE r.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "recurring schedule lookup failed",
            auth.request_id,
            &instance,
        )
    })?;

    let Some(existing) = existing else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Recurring schedule {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };
    ensure_user_group_access(pool, &auth, existing.asset_group_id, &instance).await?;

    let interval_value = payload.interval_value.unwrap_or(existing.interval_value);
    let interval_unit = payload
        .interval_unit
        .as_deref()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| existing.interval_unit.clone());
    let first_run_time = payload
        .first_run_time
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| existing.first_run_time.clone());
    let window_minutes = payload.window_minutes.unwrap_or(existing.window_minutes);
    let include_all_ignored = payload
        .include_all_ignored
        .unwrap_or(existing.include_all_ignored);
    let include_ignored_ids = payload
        .include_ignored_ids
        .unwrap_or_else(|| existing.include_ignored_ids.clone());

    let next_run_at = compute_next_recurring_run_at(
        Utc::now(),
        interval_value,
        &interval_unit,
        &first_run_time,
        window_minutes,
    )
    .map_err(|violations| {
        AppError::new(
            DomainError::Validation {
                detail: "Recurring schedule update validation failed.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.clone()),
        )
    })?;

    sqlx::query(
        r#"
        UPDATE recurring_scan_schedules
        SET interval_value = $1,
            interval_unit = $2,
            first_run_time = $3,
            window_minutes = $4,
            include_all_ignored = $5,
            include_ignored_ids = $6,
            next_run_at = $7,
            updated_at = NOW()
        WHERE id = $8
        "#,
    )
    .bind(interval_value)
    .bind(&interval_unit)
    .bind(&first_run_time)
    .bind(window_minutes)
    .bind(include_all_ignored)
    .bind(&include_ignored_ids)
    .bind(next_run_at)
    .bind(id)
    .execute(pool)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "recurring schedule update failed",
            auth.request_id,
            &instance,
        )
    })?;

    let updated: RecurringScanRow = sqlx::query_as(
        r#"
        SELECT r.id, r.asset_group_id, ag.name AS asset_group_name,
               r.interval_value, r.interval_unit, r.first_run_time, r.window_minutes,
               r.include_all_ignored, r.include_ignored_ids,
               r.last_run_at, r.last_scan_run_id, r.next_run_at,
               r.created_by, r.created_at, r.updated_at
        FROM recurring_scan_schedules r
        INNER JOIN asset_groups ag ON ag.id = r.asset_group_id
        WHERE r.id = $1
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "recurring reload failed", auth.request_id, &instance))?;

    let _ = insert_audit_log(
        pool,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "recurring_scan.updated",
            resource_type: "recurring_scan_schedule",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "interval_value": interval_value,
                "interval_unit": interval_unit,
                "first_run_time": first_run_time,
                "window_minutes": window_minutes,
                "next_run_at": next_run_at,
            })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await;

    Ok(Json(RecurringScanScheduleDto::from(updated)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/scans/recurring/{id}",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Recurring scan schedule UUID")),
    responses(
        (status = 204, description = "Recurring schedule stopped and deleted"),
        (status = 404, description = "Schedule not found", body = ProblemDetails)
    )
)]
pub async fn delete_recurring_scan(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/scans/recurring/{id}");
    auth.require(Permission::RunOrStopScans, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    if let Some(group_id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT asset_group_id FROM recurring_scan_schedules WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "recurring lookup failed", auth.request_id, &instance))?
    {
        ensure_user_group_access(pool, &auth, group_id, &instance).await?;
    }

    let res = sqlx::query("DELETE FROM recurring_scan_schedules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|err| map_db_err(err, "recurring delete failed", auth.request_id, &instance))?;

    if res.rows_affected() == 0 {
        return Err(AppError::new(
            DomainError::NotFound(format!("Recurring schedule {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    }

    let _ = insert_audit_log(
        pool,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "recurring_scan.deleted",
            resource_type: "recurring_scan_schedule",
            resource_id: Some(id),
            before_state: None,
            after_state: None,
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/scans/recurring/{id}/run-now",
    tag = "Scans",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Recurring scan schedule UUID")),
    responses(
        (status = 201, description = "Triggered recurring scan run immediately", body = ScanRunDto),
        (status = 404, description = "Schedule not found", body = ProblemDetails)
    )
)]
pub async fn trigger_recurring_scan_now(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<ScanRunDto>), AppError> {
    let instance = format!("/api/v1/scans/recurring/{id}/run-now");
    auth.require(Permission::RunOrStopScans, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let row: Option<RecurringScanRow> = sqlx::query_as(
        r#"
        SELECT r.id, r.asset_group_id, ag.name AS asset_group_name,
               r.interval_value, r.interval_unit, r.first_run_time, r.window_minutes,
               r.include_all_ignored, r.include_ignored_ids,
               r.last_run_at, r.last_scan_run_id, r.next_run_at,
               r.created_by, r.created_at, r.updated_at
        FROM recurring_scan_schedules r
        INNER JOIN asset_groups ag ON ag.id = r.asset_group_id
        WHERE r.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "recurring lookup failed", auth.request_id, &instance))?;

    let Some(schedule) = row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Recurring schedule {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };
    ensure_user_group_access(pool, &auth, schedule.asset_group_id, &instance).await?;

    let dto = enqueue_scan_run_for_group(EnqueueScanParams {
        state: &state,
        pool,
        asset_group_id: schedule.asset_group_id,
        trigger: ScanTriggerType::Scheduled,
        time_slot: None,
        started_by: Some(auth.user.id),
        include_ignored_ids: schedule.include_ignored_ids.clone(),
        include_all_ignored: schedule.include_all_ignored,
        source_ip,
        request_id: auth.request_id,
        instance: &instance,
    })
    .await?;

    let step_minutes = if schedule.interval_unit == "hours" {
        i64::from(schedule.interval_value).saturating_mul(60)
    } else {
        i64::from(schedule.interval_value)
    }
    .max(1);
    let next_run_at = Utc::now() + chrono::Duration::minutes(step_minutes);

    sqlx::query(
        r#"
        UPDATE recurring_scan_schedules
        SET last_run_at = NOW(),
            last_scan_run_id = $1,
            next_run_at = $2,
            updated_at = NOW()
        WHERE id = $3
        "#,
    )
    .bind(dto.id)
    .bind(next_run_at)
    .bind(id)
    .execute(pool)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "recurring schedule advance failed",
            auth.request_id,
            &instance,
        )
    })?;

    Ok((StatusCode::CREATED, Json(dto)))
}

#[cfg(test)]
mod recurring_tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn compute_next_run_advances_past_now() {
        let now = Utc.with_ymd_and_hms(2026, 11, 22, 9, 0, 0).unwrap();
        let next = compute_next_recurring_run_at(now, 6, "hours", "02:00", 120).unwrap();
        // 02:00 Warsaw (UTC+1) = 01:00 UTC -> +6h = 07:00 UTC -> +6h = 13:00 UTC (> 09:00 UTC)
        assert_eq!(next, Utc.with_ymd_and_hms(2026, 11, 22, 13, 0, 0).unwrap());

        let next_future = compute_next_recurring_run_at(now, 15, "minutes", "15:00", 60).unwrap();
        // 15:00 Warsaw (UTC+1) = 14:00 UTC (> 09:00 UTC)
        assert_eq!(
            next_future,
            Utc.with_ymd_and_hms(2026, 11, 22, 14, 0, 0).unwrap()
        );

        assert!(compute_next_recurring_run_at(now, 0, "hours", "02:00", 120).is_err());
        assert!(compute_next_recurring_run_at(now, 5, "days", "02:00", 120).is_err());
        assert!(compute_next_recurring_run_at(now, 5, "minutes", "25:99", 120).is_err());
    }
}
