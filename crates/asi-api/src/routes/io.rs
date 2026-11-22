use asi_common::assets::TargetType;
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::io::{
    ExportDiffsEnvelope, ExportHostsEnvelope, ExportIgnoredTargetsEnvelope, ExportPoliciesEnvelope,
    ExportServicesEnvelope, ExportTargetItem, ExportTargetsEnvelope, ImportTargetsJsonRequest,
    ImportTargetsJsonResponse, EXPORT_SCHEMA_VERSION,
};
use asi_common::rbac::Permission;
use asi_common::validation::validate_target_value;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
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
use crate::routes::diffs::DiffEventRow;
use crate::routes::hosts::HostSummaryRow;
use crate::routes::ignored_targets::IgnoredTargetRow;
use crate::routes::policies::ScanPolicyRow;
use crate::routes::services::ServiceRow;
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct GroupScopeQuery {
    pub asset_group_id: Option<Uuid>,
}

#[derive(FromRow)]
struct ExportTargetRow {
    asset_group_id: Uuid,
    asset_group_name: String,
    target_type: String,
    value: String,
    notes: Option<String>,
    created_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/api/v1/import/targets",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    request_body = ImportTargetsJsonRequest,
    responses(
        (status = 200, description = "JSON targets validated and imported", body = ImportTargetsJsonResponse),
        (status = 404, description = "Target asset group not found", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn import_targets_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ImportTargetsJsonRequest>,
) -> Result<Json<ImportTargetsJsonResponse>, AppError> {
    let instance = "/api/v1/import/targets";
    auth.require(Permission::ImportData, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut violations = Vec::new();
    if payload.schema_version.trim() != EXPORT_SCHEMA_VERSION {
        violations.push(FieldViolation {
            field: "schema_version".to_string(),
            code: "UNSUPPORTED_SCHEMA_VERSION".to_string(),
            message: format!("Expected schema_version '{EXPORT_SCHEMA_VERSION}'."),
        });
    }
    if payload.items.is_empty() {
        violations.push(FieldViolation {
            field: "items".to_string(),
            code: "REQUIRED".to_string(),
            message: "At least one target item is required.".to_string(),
        });
    }

    let mut normalized = Vec::with_capacity(payload.items.len());
    for (idx, item) in payload.items.iter().enumerate() {
        match validate_target_value(
            &format!("items[{idx}].value"),
            item.target_type,
            &item.value,
        ) {
            Ok(norm) => normalized.push((item.target_type, norm, item.notes.clone())),
            Err(violation) => violations.push(violation),
        }
    }

    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "JSON target import failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let group_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM asset_groups WHERE id = $1)")
            .bind(payload.asset_group_id)
            .fetch_one(pool)
            .await
            .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, instance))?;

    if !group_exists {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {} not found.", payload.asset_group_id)),
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let received_count = normalized.len();

    if payload.dry_run {
        let mut would_insert = 0usize;
        let mut seen = std::collections::HashSet::new();
        for (target_type, value, _) in normalized {
            let key = (target_type.as_db_str(), value);
            if !seen.insert(key.clone()) {
                continue;
            }
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM asset_group_targets WHERE asset_group_id = $1 AND target_type = $2 AND value = $3)",
            )
            .bind(payload.asset_group_id)
            .bind(key.0)
            .bind(&key.1)
            .fetch_one(pool)
            .await
            .map_err(|err| map_db_err(err, "dry run check failed", auth.request_id, instance))?;
            if !exists {
                would_insert += 1;
            }
        }
        return Ok(Json(ImportTargetsJsonResponse {
            schema_version: EXPORT_SCHEMA_VERSION.to_string(),
            dry_run: true,
            asset_group_id: payload.asset_group_id,
            received_count,
            inserted_count: would_insert,
            skipped_duplicates: received_count.saturating_sub(would_insert),
        }));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, instance))?;

    let mut inserted_count = 0usize;
    for (target_type, value, notes) in normalized {
        let res = sqlx::query(
            r#"
            INSERT INTO asset_group_targets (asset_group_id, target_type, value, notes)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (asset_group_id, target_type, value) DO NOTHING
            "#,
        )
        .bind(payload.asset_group_id)
        .bind(target_type.as_db_str())
        .bind(&value)
        .bind(notes)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "target insert failed", auth.request_id, instance))?;

        if res.rows_affected() > 0 {
            inserted_count += 1;
        }
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "targets.imported_json",
            resource_type: "asset_group",
            resource_id: Some(payload.asset_group_id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "received_count": received_count,
                "inserted_count": inserted_count,
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

    Ok(Json(ImportTargetsJsonResponse {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        dry_run: false,
        asset_group_id: payload.asset_group_id,
        received_count,
        inserted_count,
        skipped_duplicates: received_count.saturating_sub(inserted_count),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/targets",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Versioned JSON export of targets", body = ExportTargetsEnvelope)
    )
)]
pub async fn export_targets_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<Json<ExportTargetsEnvelope>, AppError> {
    let instance = "/api/v1/export/targets";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<ExportTargetRow> = sqlx::query_as(
        r#"
        SELECT agt.asset_group_id, ag.name AS asset_group_name, agt.target_type, agt.value, agt.notes, agt.created_at
        FROM asset_group_targets agt
        INNER JOIN asset_groups ag ON ag.id = agt.asset_group_id
        WHERE ($1::uuid IS NULL OR agt.asset_group_id = $1)
        ORDER BY ag.name ASC, agt.created_at ASC
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "export failed", auth.request_id, instance))?;

    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let target_type = TargetType::from_db_str(&row.target_type).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid target_type '{}'", row.target_type)),
                auth.request_id,
                Some(instance.to_string()),
            )
        })?;
        items.push(ExportTargetItem {
            asset_group_id: row.asset_group_id,
            asset_group_name: row.asset_group_name,
            target_type,
            value: row.value,
            notes: row.notes,
            created_at: row.created_at,
        });
    }

    Ok(Json(ExportTargetsEnvelope {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        exported_at: Utc::now(),
        entity_type: "targets".to_string(),
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/policies",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Versioned JSON export of scan policies", body = ExportPoliciesEnvelope)
    )
)]
pub async fn export_policies_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<ExportPoliciesEnvelope>, AppError> {
    let instance = "/api/v1/export/policies";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<ScanPolicyRow> = sqlx::query_as(
        r#"
        SELECT id, name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms, subnet_concurrency,
               kill_grace_seconds, inactivity_threshold, tarpit_port_threshold, enable_nuclei, time_windows,
               created_at, updated_at
        FROM scan_policies
        ORDER BY name ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "export failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ExportPoliciesEnvelope {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        exported_at: Utc::now(),
        entity_type: "scan_policies".to_string(),
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/ignored-targets",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Versioned JSON export of ignored targets", body = ExportIgnoredTargetsEnvelope)
    )
)]
pub async fn export_ignored_targets_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<Json<ExportIgnoredTargetsEnvelope>, AppError> {
    let instance = "/api/v1/export/ignored-targets";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<IgnoredTargetRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, target_type, value, reason, created_by, created_at
        FROM ignored_targets
        WHERE ($1::uuid IS NULL OR asset_group_id = $1)
        ORDER BY created_at DESC
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "export failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ExportIgnoredTargetsEnvelope {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        exported_at: Utc::now(),
        entity_type: "ignored_targets".to_string(),
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/hosts",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Versioned JSON export of discovered hosts inventory", body = ExportHostsEnvelope)
    )
)]
pub async fn export_hosts_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<Json<ExportHostsEnvelope>, AppError> {
    let instance = "/api/v1/export/hosts";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<HostSummaryRow> = sqlx::query_as(
        r#"
        SELECT h.id, h.asset_group_id, ag.name AS asset_group_name, h.ip_addr,
               h.status, h.consecutive_misses, h.is_unstable, h.is_probable_tarpit,
               h.availability_profile, h.auto_tags, h.manual_tags, h.notes, h.owner_hint,
               h.tarpit_override_force_sv,
               (SELECT COUNT(*) FROM host_ports hp WHERE hp.host_id = h.id AND hp.state = 'active') AS open_port_count,
               h.first_seen_at, h.last_seen_at, h.last_scanned_at
        FROM hosts h
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
        ORDER BY ag.name ASC, h.ip_addr ASC
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "hosts export failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ExportHostsEnvelope {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        exported_at: Utc::now(),
        entity_type: "hosts".to_string(),
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/diffs",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Versioned JSON export of Diff Engine events", body = ExportDiffsEnvelope)
    )
)]
pub async fn export_diffs_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<Json<ExportDiffsEnvelope>, AppError> {
    let instance = "/api/v1/export/diffs";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<DiffEventRow> = sqlx::query_as(
        r#"
        SELECT de.id, de.host_id, h.asset_group_id, h.ip_addr, de.scan_run_id,
               de.event_kind, de.severity, de.bullet_items,
               de.previous_snapshot, de.current_snapshot,
               de.acknowledged_by, de.acknowledged_at, de.detected_at
        FROM diff_events de
        INNER JOIN hosts h ON h.id = de.host_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
        ORDER BY de.detected_at DESC
        LIMIT 1000
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "diffs export failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ExportDiffsEnvelope {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        exported_at: Utc::now(),
        entity_type: "diffs".to_string(),
        items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/services",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Versioned JSON export of active services and web observations", body = ExportServicesEnvelope)
    )
)]
pub async fn export_services_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<Json<ExportServicesEnvelope>, AppError> {
    let instance = "/api/v1/export/services";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<ServiceRow> = sqlx::query_as(
        r#"
        SELECT h.id AS host_id, hp.id AS host_port_id, h.asset_group_id,
               ag.name AS asset_group_name, h.ip_addr, hp.port, hp.protocol, hp.state,
               hp.service_name, hp.product, hp.version, hp.tunnel,
               wo.vhost, wo.scheme, wo.http_status, wo.title, wo.favicon_mmh3,
               wo.matched_technologies, wo.detected_paths,
               GREATEST(hp.last_seen_at, COALESCE(wo.last_observed_at, hp.last_seen_at)) AS last_seen_at
        FROM host_ports hp
        INNER JOIN hosts h ON h.id = hp.host_id
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        LEFT JOIN web_observations wo ON wo.host_port_id = hp.id
        WHERE hp.state <> 'closed'
          AND ($1::uuid IS NULL OR h.asset_group_id = $1)
        ORDER BY h.ip_addr ASC, hp.port ASC, wo.vhost ASC NULLS LAST
        LIMIT 2000
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "services export failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(ExportServicesEnvelope {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        exported_at: Utc::now(),
        entity_type: "services".to_string(),
        items,
    }))
}
