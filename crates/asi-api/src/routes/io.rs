use asi_common::assets::{TargetInput, TargetType};
use asi_common::diff::{BulletItem, DiffEventKind, DiffOp, DiffSeverity};
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::io::{
    ExportDiffsEnvelope, ExportHostsEnvelope, ExportIgnoredTargetsEnvelope, ExportPoliciesEnvelope,
    ExportServicesEnvelope, ExportTargetItem, ExportTargetsEnvelope, ImportScanResultsRequest,
    ImportScanResultsResponse, ImportTargetsFlexibleRequest, ImportTargetsFlexibleResponse,
    ImportTargetsJsonRequest, ImportTargetsJsonResponse, ScanResultImportItem,
    EXPORT_SCHEMA_VERSION,
};
use asi_common::rbac::Permission;
use asi_common::scans::ScanTriggerType;
use asi_common::validation::{
    auto_detect_target_type, parse_raw_targets_blob, validate_target_value,
};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
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

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn format_csv_row(fields: &[String]) -> String {
    fields
        .iter()
        .map(|f| csv_escape(f))
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_response(filename: &str, body: String) -> (StatusCode, HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, disp);
    }
    (StatusCode::OK, headers, body)
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' && current.is_empty() {
            in_quotes = true;
        } else if ch == ',' {
            fields.push(current.trim().to_string());
            current = String::new();
        } else {
            current.push(ch);
        }
    }
    fields.push(current.trim().to_string());
    fields
}

fn target_from_json_value(
    item: &serde_json::Value,
    idx: usize,
) -> Result<TargetInput, FieldViolation> {
    let field_path = format!("items[{idx}]");
    if let Some(raw) = item.as_str() {
        let (target_type, value) = auto_detect_target_type(&field_path, raw)?;
        return Ok(TargetInput {
            target_type,
            value,
            notes: None,
        });
    }

    let Some(obj) = item.as_object() else {
        return Err(FieldViolation {
            field: field_path,
            code: "INVALID_FORMAT".to_string(),
            message: "Target item must be a string or object.".to_string(),
        });
    };

    let raw_value = obj
        .get("value")
        .or_else(|| obj.get("target"))
        .or_else(|| obj.get("ip"))
        .or_else(|| obj.get("host"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| FieldViolation {
            field: format!("{field_path}.value"),
            code: "REQUIRED".to_string(),
            message: "Missing target value.".to_string(),
        })?;

    let notes = obj
        .get("notes")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let val_field = format!("{field_path}.value");
    let (target_type, value) = if let Some(raw_type) = obj
        .get("target_type")
        .or_else(|| obj.get("type"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let parsed_type =
            TargetType::from_db_str(&raw_type.to_ascii_lowercase()).ok_or_else(|| {
                FieldViolation {
                    field: format!("{field_path}.target_type"),
                    code: "INVALID_TARGET_TYPE".to_string(),
                    message: format!("Unsupported target_type '{raw_type}'."),
                }
            })?;
        let canonical = validate_target_value(&val_field, parsed_type, raw_value)?;
        (parsed_type, canonical)
    } else {
        auto_detect_target_type(&val_field, raw_value)?
    };

    Ok(TargetInput {
        target_type,
        value,
        notes,
    })
}

fn parse_targets_csv(content: &str) -> Result<Vec<TargetInput>, Vec<FieldViolation>> {
    let mut out = Vec::new();
    let mut violations = Vec::new();
    let mut header_map: Option<(Option<usize>, Option<usize>, Option<usize>)> = None;

    for (line_idx, raw_line) in content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let cols = parse_csv_line(trimmed);
        let field_name = format!("line_{}", line_idx + 1);
        if header_map.is_none() {
            let lowered: Vec<String> = cols.iter().map(|c| c.to_ascii_lowercase()).collect();
            if lowered.iter().any(|c| {
                matches!(
                    c.as_str(),
                    "value" | "target" | "target_type" | "ip" | "host"
                )
            }) {
                let type_idx = lowered
                    .iter()
                    .position(|c| matches!(c.as_str(), "target_type" | "type"));
                let value_idx = lowered
                    .iter()
                    .position(|c| matches!(c.as_str(), "value" | "target" | "ip" | "host"));
                let notes_idx = lowered.iter().position(|c| c == "notes");
                header_map = Some((type_idx, value_idx, notes_idx));
                continue;
            }
            header_map = Some((None, None, None));
        }

        match header_map {
            Some((type_idx, Some(value_idx), notes_idx)) => {
                let raw_val = cols.get(value_idx).map(String::as_str).unwrap_or("").trim();
                if raw_val.is_empty() {
                    continue;
                }
                let notes = notes_idx
                    .and_then(|i| cols.get(i))
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string);
                let parsed = if let Some(t_str) = type_idx
                    .and_then(|i| cols.get(i))
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    match TargetType::from_db_str(&t_str.to_ascii_lowercase()) {
                        Some(tt) => {
                            validate_target_value(&field_name, tt, raw_val).map(|v| (tt, v))
                        }
                        None => Err(FieldViolation {
                            field: field_name.clone(),
                            code: "INVALID_TARGET_TYPE".to_string(),
                            message: format!("Unsupported target_type '{t_str}'."),
                        }),
                    }
                } else {
                    auto_detect_target_type(&field_name, raw_val)
                };
                match parsed {
                    Ok((target_type, value)) => out.push(TargetInput {
                        target_type,
                        value,
                        notes,
                    }),
                    Err(v) => violations.push(v),
                }
            }
            _ => {
                if cols.len() >= 2
                    && TargetType::from_db_str(&cols[0].to_ascii_lowercase()).is_some()
                {
                    let tt = TargetType::from_db_str(&cols[0].to_ascii_lowercase())
                        .unwrap_or(TargetType::Ip);
                    match validate_target_value(&field_name, tt, &cols[1]) {
                        Ok(value) => out.push(TargetInput {
                            target_type: tt,
                            value,
                            notes: cols
                                .get(2)
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .map(ToString::to_string),
                        }),
                        Err(v) => violations.push(v),
                    }
                } else {
                    for cell in cols {
                        if cell.is_empty() {
                            continue;
                        }
                        match auto_detect_target_type(&field_name, &cell) {
                            Ok((target_type, value)) => out.push(TargetInput {
                                target_type,
                                value,
                                notes: None,
                            }),
                            Err(v) => violations.push(v),
                        }
                    }
                }
            }
        }
    }

    if !violations.is_empty() {
        return Err(violations);
    }
    if out.is_empty() {
        return Err(vec![FieldViolation {
            field: "content".to_string(),
            code: "EMPTY".to_string(),
            message: "No valid targets found in CSV input.".to_string(),
        }]);
    }
    Ok(out)
}

fn parse_flexible_targets(
    format: Option<&str>,
    content: &str,
) -> Result<Vec<TargetInput>, Vec<FieldViolation>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(vec![FieldViolation {
            field: "content".to_string(),
            code: "EMPTY".to_string(),
            message: "Target payload must not be empty.".to_string(),
        }]);
    }

    let fmt_norm = format.unwrap_or("auto").trim().to_ascii_lowercase();
    let effective = if fmt_norm.is_empty() || fmt_norm == "auto" {
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            "json"
        } else {
            let first_non_comment = trimmed
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with('#'))
                .unwrap_or("");
            let first_cols = parse_csv_line(first_non_comment);
            let is_csv_header = first_cols.iter().any(|c| {
                matches!(
                    c.to_ascii_lowercase().as_str(),
                    "target_type" | "type" | "value" | "target" | "asset_group_name"
                )
            });
            if is_csv_header
                || (first_cols.len() >= 2
                    && TargetType::from_db_str(&first_cols[0].to_ascii_lowercase()).is_some())
            {
                "csv"
            } else {
                "raw"
            }
        }
    } else {
        fmt_norm.as_str()
    };

    match effective {
        "json" => {
            let parsed: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
                vec![FieldViolation {
                    field: "content".to_string(),
                    code: "INVALID_JSON".to_string(),
                    message: format!("Invalid JSON target payload: {err}"),
                }]
            })?;
            let items: &[serde_json::Value] = if let Some(arr) = parsed.as_array() {
                arr
            } else if let Some(arr) = parsed.get("items").and_then(|v| v.as_array()) {
                arr
            } else if let Some(arr) = parsed.get("targets").and_then(|v| v.as_array()) {
                arr
            } else {
                return Err(vec![FieldViolation {
                    field: "content".to_string(),
                    code: "INVALID_JSON_SHAPE".to_string(),
                    message: "JSON must be an array or an object containing 'items' or 'targets'."
                        .to_string(),
                }]);
            };
            let mut out = Vec::with_capacity(items.len());
            let mut violations = Vec::new();
            for (idx, item) in items.iter().enumerate() {
                match target_from_json_value(item, idx) {
                    Ok(t) => out.push(t),
                    Err(v) => violations.push(v),
                }
            }
            if !violations.is_empty() {
                return Err(violations);
            }
            if out.is_empty() {
                return Err(vec![FieldViolation {
                    field: "content".to_string(),
                    code: "EMPTY".to_string(),
                    message: "JSON payload contained zero targets.".to_string(),
                }]);
            }
            Ok(out)
        }
        "csv" => parse_targets_csv(trimmed),
        "raw" => parse_raw_targets_blob(trimmed),
        other => Err(vec![FieldViolation {
            field: "format".to_string(),
            code: "UNSUPPORTED_FORMAT".to_string(),
            message: format!("Unsupported target import format '{other}'."),
        }]),
    }
}

fn split_list_cell(cell: &str) -> Vec<String> {
    cell.split([';', '|'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect()
}

struct ParsedScanResult {
    item: ScanResultImportItem,
    detected_paths: Vec<String>,
}

fn parse_scan_results_input(
    format: Option<&str>,
    content: Option<&str>,
    items: &[ScanResultImportItem],
) -> Result<Vec<ParsedScanResult>, Vec<FieldViolation>> {
    if !items.is_empty() {
        return Ok(items
            .iter()
            .cloned()
            .map(|item| {
                let mut paths = Vec::new();
                if let Some(ref notes) = item.notes {
                    let lower = notes.to_ascii_lowercase();
                    if lower.contains("/admin") {
                        paths.push("/admin".to_string());
                    }
                    if lower.contains("/login") {
                        paths.push("/login".to_string());
                    }
                }
                ParsedScanResult {
                    item,
                    detected_paths: paths,
                }
            })
            .collect());
    }
    let trimmed = content.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Err(vec![FieldViolation {
            field: "content".to_string(),
            code: "EMPTY".to_string(),
            message: "Provide either 'items' or non-empty 'content'.".to_string(),
        }]);
    }
    let fmt_norm = format.unwrap_or("auto").trim().to_ascii_lowercase();
    let effective = if fmt_norm.is_empty() || fmt_norm == "auto" {
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            "json"
        } else {
            "csv"
        }
    } else {
        fmt_norm.as_str()
    };

    match effective {
        "json" => {
            let val: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
                vec![FieldViolation {
                    field: "content".to_string(),
                    code: "INVALID_JSON".to_string(),
                    message: format!("Invalid scan results JSON: {err}"),
                }]
            })?;
            let arr_val = if val.is_array() {
                val
            } else if let Some(inner) = val.get("items").cloned() {
                inner
            } else {
                return Err(vec![FieldViolation {
                    field: "content".to_string(),
                    code: "INVALID_JSON_SHAPE".to_string(),
                    message: "JSON must be an array or an object with 'items'.".to_string(),
                }]);
            };
            let decoded: Vec<ScanResultImportItem> = serde_json::from_value(arr_val.clone())
                .map_err(|err| {
                    vec![FieldViolation {
                        field: "content".to_string(),
                        code: "INVALID_SCAN_ITEM".to_string(),
                        message: format!("Failed to deserialize scan result items: {err}"),
                    }]
                })?;
            let raw_arr = arr_val.as_array().cloned().unwrap_or_default();
            Ok(decoded
                .into_iter()
                .enumerate()
                .map(|(i, item)| {
                    let mut paths: Vec<String> = raw_arr
                        .get(i)
                        .and_then(|v| v.get("detected_paths"))
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    if paths.is_empty() {
                        if let Some(ref notes) = item.notes {
                            let lower = notes.to_ascii_lowercase();
                            if lower.contains("/admin") {
                                paths.push("/admin".to_string());
                            }
                            if lower.contains("/login") {
                                paths.push("/login".to_string());
                            }
                        }
                    }
                    ParsedScanResult {
                        item,
                        detected_paths: paths,
                    }
                })
                .collect())
        }
        "csv" => {
            let mut lines = trimmed
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'));
            let Some(header_line) = lines.next() else {
                return Err(vec![FieldViolation {
                    field: "content".to_string(),
                    code: "EMPTY".to_string(),
                    message: "CSV scan results payload is empty.".to_string(),
                }]);
            };
            let headers: Vec<String> = parse_csv_line(header_line)
                .into_iter()
                .map(|h| h.to_ascii_lowercase())
                .collect();
            let col_idx = |names: &[&str]| -> Option<usize> {
                headers.iter().position(|h| names.contains(&h.as_str()))
            };
            let Some(ip_idx) = col_idx(&["ip_addr", "ip", "host"]) else {
                return Err(vec![FieldViolation {
                    field: "content".to_string(),
                    code: "MISSING_COLUMN".to_string(),
                    message: "CSV header must contain 'ip_addr', 'ip', or 'host'.".to_string(),
                }]);
            };
            let port_idx = col_idx(&["port"]);
            let proto_idx = col_idx(&["protocol", "proto"]);
            let svc_idx = col_idx(&["service_name", "service"]);
            let product_idx = col_idx(&["product"]);
            let version_idx = col_idx(&["version"]);
            let vhost_idx = col_idx(&["vhost"]);
            let scheme_idx = col_idx(&["scheme"]);
            let http_idx = col_idx(&["http_status", "status"]);
            let title_idx = col_idx(&["title"]);
            let tech_idx = col_idx(&["matched_technologies", "technologies"]);
            let notes_idx = col_idx(&["notes"]);
            let paths_idx = col_idx(&["detected_paths", "paths"]);

            let mut parsed_items = Vec::new();
            for (row_no, line) in lines.enumerate() {
                let cols = parse_csv_line(line);
                let ip_addr = cols.get(ip_idx).map(|s| s.trim()).unwrap_or("").to_string();
                if ip_addr.is_empty() {
                    continue;
                }
                let port = match port_idx
                    .and_then(|i| cols.get(i))
                    .map(String::as_str)
                    .map(str::trim)
                {
                    Some(raw_p) if !raw_p.is_empty() => {
                        let p = raw_p.parse::<u16>().map_err(|_| {
                            vec![FieldViolation {
                                field: format!("row_{}.port", row_no + 2),
                                code: "INVALID_PORT".to_string(),
                                message: format!("Invalid port number '{raw_p}'."),
                            }]
                        })?;
                        if p == 0 {
                            return Err(vec![FieldViolation {
                                field: format!("row_{}.port", row_no + 2),
                                code: "INVALID_PORT".to_string(),
                                message: "Port must be between 1 and 65535.".to_string(),
                            }]);
                        }
                        p
                    }
                    _ => 80,
                };
                let http_status = match http_idx
                    .and_then(|i| cols.get(i))
                    .map(String::as_str)
                    .map(str::trim)
                {
                    Some(raw_s) if !raw_s.is_empty() => {
                        Some(raw_s.parse::<u16>().map_err(|_| {
                            vec![FieldViolation {
                                field: format!("row_{}.http_status", row_no + 2),
                                code: "INVALID_HTTP_STATUS".to_string(),
                                message: format!("Invalid HTTP status '{raw_s}'."),
                            }]
                        })?)
                    }
                    _ => None,
                };
                let opt_str = |idx: Option<usize>| -> Option<String> {
                    idx.and_then(|i| cols.get(i))
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(ToString::to_string)
                };
                let protocol = opt_str(proto_idx).unwrap_or_else(|| "tcp".to_string());
                let detected_paths = paths_idx
                    .and_then(|i| cols.get(i))
                    .map(|s| split_list_cell(s))
                    .unwrap_or_default();
                parsed_items.push(ParsedScanResult {
                    item: ScanResultImportItem {
                        ip_addr,
                        port,
                        protocol,
                        service_name: opt_str(svc_idx),
                        product: opt_str(product_idx),
                        version: opt_str(version_idx),
                        vhost: opt_str(vhost_idx),
                        scheme: opt_str(scheme_idx),
                        http_status,
                        title: opt_str(title_idx),
                        technologies: tech_idx
                            .and_then(|i| cols.get(i))
                            .map(|s| split_list_cell(s))
                            .unwrap_or_default(),
                        notes: opt_str(notes_idx),
                    },
                    detected_paths,
                });
            }
            if parsed_items.is_empty() {
                return Err(vec![FieldViolation {
                    field: "content".to_string(),
                    code: "EMPTY".to_string(),
                    message: "CSV scan results payload contained zero rows.".to_string(),
                }]);
            }
            Ok(parsed_items)
        }
        other => Err(vec![FieldViolation {
            field: "format".to_string(),
            code: "UNSUPPORTED_FORMAT".to_string(),
            message: format!("Unsupported scan results import format '{other}'."),
        }]),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/import/targets-flexible",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    request_body = ImportTargetsFlexibleRequest,
    responses(
        (status = 200, description = "Flexible target import result", body = ImportTargetsFlexibleResponse),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn import_targets_flexible(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ImportTargetsFlexibleRequest>,
) -> Result<Json<ImportTargetsFlexibleResponse>, AppError> {
    let instance = "/api/v1/import/targets-flexible";
    auth.require(Permission::ImportData, instance)?;
    if payload.start_scan {
        auth.require(Permission::RunOrStopScans, instance)?;
    }

    let targets = parse_flexible_targets(payload.format.as_deref(), &payload.content).map_err(
        |violations| {
            AppError::new(
                DomainError::Validation {
                    detail: "Target import validation failed.".to_string(),
                    violations,
                },
                auth.request_id,
                Some(instance.to_string()),
            )
        },
    )?;

    let mut summary_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for t in &targets {
        *summary_counts
            .entry(t.target_type.as_db_str().to_string())
            .or_insert(0) += 1;
    }

    if payload.dry_run {
        return Ok(Json(ImportTargetsFlexibleResponse {
            asset_group_id: payload.asset_group_id.unwrap_or_else(Uuid::nil),
            asset_group_name: payload
                .new_group_name
                .clone()
                .unwrap_or_else(|| "dry-run".to_string()),
            dry_run: true,
            received_count: targets.len(),
            inserted_count: 0,
            skipped_duplicates: 0,
            detected_summary: summary_counts,
            started_scan_run_id: None,
        }));
    }

    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);
    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, instance))?;

    let (group_id, resolved_name): (Uuid, String) = if let Some(gid) = payload.asset_group_id {
        let existing: Option<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM asset_groups WHERE id = $1")
                .bind(gid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|err| map_db_err(err, "group lookup failed", auth.request_id, instance))?;
        let Some(found) = existing else {
            return Err(AppError::new(
                DomainError::NotFound(format!("Asset group {gid} not found.")),
                auth.request_id,
                Some(instance.to_string()),
            ));
        };
        found
    } else {
        let desired_name = payload
            .new_group_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("Import {}", Utc::now().format("%Y-%m-%d %H:%M:%S")));

        let existing: Option<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM asset_groups WHERE name = $1")
                .bind(&desired_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|err| map_db_err(err, "group lookup failed", auth.request_id, instance))?;

        if let Some(found) = existing {
            found
        } else {
            let policy_id: Uuid = if let Some(pid) = sqlx::query_scalar::<_, Uuid>(
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
                .map_err(|err| map_db_err(err, "default policy insert failed", auth.request_id, instance))?
            };

            let created_id: Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO asset_groups (name, description, policy_id, sampling_enabled, created_by)
                VALUES ($1, 'Auto-created during flexible target import', $2, FALSE, $3)
                RETURNING id
                "#,
            )
            .bind(&desired_name)
            .bind(policy_id)
            .bind(auth.user.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "group insert failed", auth.request_id, instance))?;
            (created_id, desired_name)
        }
    };

    let mut inserted_count = 0usize;
    let mut skipped_duplicates = 0usize;
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
        .map_err(|err| map_db_err(err, "target insert failed", auth.request_id, instance))?;
        if res.rows_affected() > 0 {
            inserted_count += 1;
        } else {
            skipped_duplicates += 1;
        }
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "io.import_targets_flexible",
            resource_type: "asset_group",
            resource_id: Some(group_id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "received_count": targets.len(),
                "inserted_count": inserted_count,
                "skipped_duplicates": skipped_duplicates,
                "start_scan": payload.start_scan,
            })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "tx commit failed", auth.request_id, instance))?;

    let started_scan_run_id = if payload.start_scan {
        let run = crate::routes::scans::enqueue_scan_run_for_group(
            crate::routes::scans::EnqueueScanParams {
                state: &state,
                pool,
                asset_group_id: group_id,
                trigger: ScanTriggerType::Manual,
                time_slot: None,
                started_by: Some(auth.user.id),
                include_ignored_ids: Vec::new(),
                include_all_ignored: false,
                source_ip,
                request_id: auth.request_id,
                instance,
            },
        )
        .await?;
        Some(run.id)
    } else {
        None
    };

    Ok(Json(ImportTargetsFlexibleResponse {
        asset_group_id: group_id,
        asset_group_name: resolved_name,
        dry_run: false,
        received_count: targets.len(),
        inserted_count,
        skipped_duplicates,
        detected_summary: summary_counts,
        started_scan_run_id,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/import/scan-results",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    request_body = ImportScanResultsRequest,
    responses(
        (status = 200, description = "Imported scan results into inventory and emitted diffs", body = ImportScanResultsResponse),
        (status = 403, description = "Forbidden", body = ProblemDetails),
        (status = 404, description = "Asset group not found", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn import_scan_results(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ImportScanResultsRequest>,
) -> Result<Json<ImportScanResultsResponse>, AppError> {
    let instance = "/api/v1/import/scan-results";
    auth.require(Permission::ImportData, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let parsed_items = parse_scan_results_input(
        payload.format.as_deref(),
        payload.content.as_deref(),
        &payload.items,
    )
    .map_err(|violations| {
        AppError::new(
            DomainError::Validation {
                detail: "Scan results payload validation failed.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        )
    })?;

    // Validate all IP addresses, ports, protocols, and web schemes upfront before opening a DB tx.
    let mut validated_items: Vec<(ipnetwork::IpNetwork, ParsedScanResult)> =
        Vec::with_capacity(parsed_items.len());
    let mut violations = Vec::new();
    for (idx, entry) in parsed_items.into_iter().enumerate() {
        let ip_raw = entry.item.ip_addr.trim();
        let Ok(ip_addr) = ip_raw.parse::<std::net::IpAddr>() else {
            violations.push(FieldViolation {
                field: format!("items[{idx}].ip_addr"),
                code: "INVALID_IP".to_string(),
                message: format!("Invalid IP address '{ip_raw}'."),
            });
            continue;
        };
        if entry.item.port == 0 {
            violations.push(FieldViolation {
                field: format!("items[{idx}].port"),
                code: "INVALID_PORT".to_string(),
                message: "Port must be between 1 and 65535.".to_string(),
            });
            continue;
        }
        let proto_norm = entry.item.protocol.trim().to_ascii_lowercase();
        if proto_norm != "tcp" && proto_norm != "udp" {
            violations.push(FieldViolation {
                field: format!("items[{idx}].protocol"),
                code: "INVALID_PROTOCOL".to_string(),
                message: "Protocol must be 'tcp' or 'udp'.".to_string(),
            });
            continue;
        }
        if let Some(ref scheme) = entry.item.scheme {
            let s_norm = scheme.trim().to_ascii_lowercase();
            if s_norm != "http" && s_norm != "https" {
                violations.push(FieldViolation {
                    field: format!("items[{idx}].scheme"),
                    code: "INVALID_SCHEME".to_string(),
                    message: "Web scheme must be 'http' or 'https'.".to_string(),
                });
                continue;
            }
        }
        validated_items.push((ipnetwork::IpNetwork::from(ip_addr), entry));
    }
    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Scan results items failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, instance))?;

    let group_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM asset_groups WHERE id = $1)")
            .bind(payload.asset_group_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "group lookup failed", auth.request_id, instance))?;
    if !group_exists {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {} not found.", payload.asset_group_id)),
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let now = Utc::now();
    let mut hosts_upserted = 0usize;
    let mut ports_upserted = 0usize;
    let mut web_observations_upserted = 0usize;
    let mut diff_events_created = 0usize;
    let mut host_bullets: std::collections::BTreeMap<Uuid, (String, Vec<BulletItem>, bool)> =
        std::collections::BTreeMap::new();

    for (ip_net, entry_item) in validated_items {
        let item = entry_item.item;
        let detected_paths = entry_item.detected_paths;
        let mut auto_tags: Vec<String> = Vec::new();
        if detected_paths
            .iter()
            .any(|p| p == "/admin" || p == "/login")
        {
            auto_tags.push("admin-panel".to_string());
        }

        let (host_id, newly_inserted): (Uuid, bool) = sqlx::query_as(
            r#"
            INSERT INTO hosts (
                asset_group_id, ip_addr, status, consecutive_misses,
                is_unstable, is_probable_tarpit, availability_profile, auto_tags,
                notes, first_seen_at, last_seen_at, last_scanned_at
            )
            VALUES ($1, $2, 'active', 0, FALSE, FALSE, '{}'::jsonb, $3, $4, $5, $5, $5)
            ON CONFLICT (asset_group_id, ip_addr) DO UPDATE
            SET status = CASE WHEN hosts.status = 'ignored' THEN 'ignored' ELSE 'active' END,
                consecutive_misses = 0,
                notes = COALESCE(EXCLUDED.notes, hosts.notes),
                last_seen_at = EXCLUDED.last_seen_at,
                last_scanned_at = EXCLUDED.last_scanned_at
            RETURNING id, (xmax = 0)
            "#,
        )
        .bind(payload.asset_group_id)
        .bind(ip_net)
        .bind(&auto_tags)
        .bind(&item.notes)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "host upsert failed", auth.request_id, instance))?;
        hosts_upserted += 1;

        let host_entry = host_bullets
            .entry(host_id)
            .or_insert_with(|| (item.ip_addr.clone(), Vec::new(), newly_inserted));
        if newly_inserted && !host_entry.1.iter().any(|b| b.key == "host_discovered") {
            host_entry.1.push(BulletItem {
                op: DiffOp::Added,
                key: "host_discovered".to_string(),
                params: serde_json::json!({ "ip": item.ip_addr }),
            });
        }

        let port = item.port;
        let proto = item.protocol.trim().to_ascii_lowercase();
        let port_i32 = i32::from(port);

        let existing_port: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM host_ports WHERE host_id = $1 AND port = $2 AND protocol = $3",
        )
        .bind(host_id)
        .bind(port_i32)
        .bind(&proto)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "port lookup failed", auth.request_id, instance))?;

        let host_port_id = if let Some(pid) = existing_port {
            sqlx::query(
                r#"
                UPDATE host_ports
                SET state = 'active',
                    consecutive_misses = 0,
                    service_name = COALESCE($1, service_name),
                    product = COALESCE($2, product),
                    version = COALESCE($3, version),
                    last_seen_at = $4
                WHERE id = $5
                "#,
            )
            .bind(&item.service_name)
            .bind(&item.product)
            .bind(&item.version)
            .bind(now)
            .bind(pid)
            .execute(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "port update failed", auth.request_id, instance))?;
            pid
        } else {
            let inserted_pid: Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO host_ports (
                    host_id, port, protocol, state, consecutive_misses,
                    service_name, product, version, first_seen_at, last_seen_at
                )
                VALUES ($1, $2, $3, 'active', 0, $4, $5, $6, $7, $7)
                RETURNING id
                "#,
            )
            .bind(host_id)
            .bind(port_i32)
            .bind(&proto)
            .bind(&item.service_name)
            .bind(&item.product)
            .bind(&item.version)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "port insert failed", auth.request_id, instance))?;

            host_entry.1.push(BulletItem {
                op: DiffOp::Added,
                key: "service_added".to_string(),
                params: serde_json::json!({
                    "port": port,
                    "proto": proto,
                    "service": item.service_name.clone().unwrap_or_else(|| "unknown".to_string()),
                }),
            });
            inserted_pid
        };
        ports_upserted += 1;

        let has_web = item.vhost.is_some()
            || item.http_status.is_some()
            || item.title.is_some()
            || !item.technologies.is_empty()
            || !detected_paths.is_empty();
        if has_web {
            let vhost = item.vhost.clone().unwrap_or_else(|| item.ip_addr.clone());
            let scheme = item
                .scheme
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_else(|| {
                    if port == 443 || port == 8443 {
                        "https".to_string()
                    } else {
                        "http".to_string()
                    }
                });
            let http_status_i32 = item.http_status.map(i32::from);
            let techs_json = serde_json::to_value(&item.technologies).map_err(|err| {
                AppError::new(
                    DomainError::Internal(format!("serialize technologies: {err}")),
                    auth.request_id,
                    Some(instance.to_string()),
                )
            })?;

            let existing_obs: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM web_observations WHERE host_port_id = $1 AND vhost = $2 AND scheme = $3",
            )
            .bind(host_port_id)
            .bind(&vhost)
            .bind(&scheme)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "web obs lookup failed", auth.request_id, instance))?;

            if let Some(oid) = existing_obs {
                sqlx::query(
                    r#"
                    UPDATE web_observations
                    SET http_status = COALESCE($1, http_status),
                        title = COALESCE($2, title),
                        matched_technologies = $3,
                        detected_paths = $4,
                        last_observed_at = $5
                    WHERE id = $6
                    "#,
                )
                .bind(http_status_i32)
                .bind(&item.title)
                .bind(&techs_json)
                .bind(&detected_paths)
                .bind(now)
                .bind(oid)
                .execute(&mut *tx)
                .await
                .map_err(|err| {
                    map_db_err(err, "web obs update failed", auth.request_id, instance)
                })?;
            } else {
                sqlx::query(
                    r#"
                    INSERT INTO web_observations (
                        host_port_id, vhost, scheme, http_status, title,
                        matched_technologies, detected_paths, last_observed_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    "#,
                )
                .bind(host_port_id)
                .bind(&vhost)
                .bind(&scheme)
                .bind(http_status_i32)
                .bind(&item.title)
                .bind(&techs_json)
                .bind(&detected_paths)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|err| {
                    map_db_err(err, "web obs insert failed", auth.request_id, instance)
                })?;
            }
            web_observations_upserted += 1;

            if detected_paths
                .iter()
                .any(|p| p == "/admin" || p == "/login")
            {
                host_entry.1.push(BulletItem {
                    op: DiffOp::Added,
                    key: "admin_panel_detected".to_string(),
                    params: serde_json::json!({
                        "port": port,
                        "vhost": vhost,
                        "paths": detected_paths,
                    }),
                });
            }
        }
    }

    for (host_id, (_ip, bullets, _)) in host_bullets {
        if bullets.is_empty() {
            continue;
        }
        let severity = if bullets.iter().any(|b| b.key == "admin_panel_detected") {
            DiffSeverity::High
        } else if bullets.iter().any(|b| b.key == "service_added") {
            DiffSeverity::Medium
        } else {
            DiffSeverity::Info
        };
        let bullets_json = serde_json::to_value(&bullets).map_err(|err| {
            AppError::new(
                DomainError::Internal(format!("serialize diff bullets: {err}")),
                auth.request_id,
                Some(instance.to_string()),
            )
        })?;
        let diff_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO diff_events (
                host_id, scan_run_id, event_kind, severity, bullet_items, detected_at
            )
            VALUES ($1, NULL, 'confirmed_change', $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(host_id)
        .bind(severity.as_db_str())
        .bind(&bullets_json)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "diff event insert failed", auth.request_id, instance))?;

        crate::notifications::worker::enqueue_notifications_for_diff(
            &mut tx,
            payload.asset_group_id,
            diff_id,
            DiffEventKind::ConfirmedChange,
        )
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "enqueue notification failed",
                auth.request_id,
                instance,
            )
        })?;

        diff_events_created += 1;
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "io.import_scan_results",
            resource_type: "asset_group",
            resource_id: Some(payload.asset_group_id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "hosts_upserted": hosts_upserted,
                "ports_upserted": ports_upserted,
                "web_observations_upserted": web_observations_upserted,
                "diff_events_created": diff_events_created,
            })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "tx commit failed", auth.request_id, instance))?;

    Ok(Json(ImportScanResultsResponse {
        asset_group_id: payload.asset_group_id,
        hosts_upserted,
        ports_upserted,
        web_observations_upserted,
        diff_events_created,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/targets.csv",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Targets exported as CSV", content_type = "text/csv"),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn export_targets_csv(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<(StatusCode, HeaderMap, String), AppError> {
    let instance = "/api/v1/export/targets.csv";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<(Uuid, String, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT t.asset_group_id, ag.name, t.target_type, t.value, t.notes
        FROM asset_group_targets t
        JOIN asset_groups ag ON ag.id = t.asset_group_id
        WHERE ($1::uuid IS NULL OR t.asset_group_id = $1)
        ORDER BY ag.name ASC, t.target_type ASC, t.value ASC
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "export targets csv failed", auth.request_id, instance))?;

    let mut lines = vec![format_csv_row(&[
        "asset_group_id".into(),
        "asset_group_name".into(),
        "target_type".into(),
        "value".into(),
        "notes".into(),
    ])];
    for (gid, gname, ttype, val, notes) in rows {
        lines.push(format_csv_row(&[
            gid.to_string(),
            gname,
            ttype,
            val,
            notes.unwrap_or_default(),
        ]));
    }
    Ok(csv_response("asi-targets.csv", lines.join("\n")))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/hosts.csv",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Hosts exported as CSV", content_type = "text/csv"),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn export_hosts_csv(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<(StatusCode, HeaderMap, String), AppError> {
    let instance = "/api/v1/export/hosts.csv";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    #[derive(sqlx::FromRow)]
    struct CsvHostRow {
        id: Uuid,
        asset_group_id: Uuid,
        group_name: String,
        ip_addr: String,
        status: String,
        is_unstable: bool,
        is_probable_tarpit: bool,
        auto_tags: Vec<String>,
        manual_tags: Vec<String>,
        owner_hint: Option<String>,
        notes: Option<String>,
        first_seen_at: DateTime<Utc>,
        last_seen_at: Option<DateTime<Utc>>,
    }

    let rows: Vec<CsvHostRow> = sqlx::query_as(
        r#"
        SELECT h.id, h.asset_group_id, ag.name AS group_name, h.ip_addr::text AS ip_addr,
               h.status, h.is_unstable, h.is_probable_tarpit,
               h.auto_tags, h.manual_tags, h.owner_hint, h.notes,
               h.first_seen_at, h.last_seen_at
        FROM hosts h
        JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
        ORDER BY ag.name ASC, h.ip_addr ASC
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "export hosts csv failed", auth.request_id, instance))?;

    let mut lines = vec![format_csv_row(&[
        "host_id".into(),
        "asset_group_id".into(),
        "asset_group_name".into(),
        "ip_addr".into(),
        "status".into(),
        "is_unstable".into(),
        "is_probable_tarpit".into(),
        "auto_tags".into(),
        "manual_tags".into(),
        "owner_hint".into(),
        "notes".into(),
        "first_seen_at".into(),
        "last_seen_at".into(),
    ])];
    for r in rows {
        lines.push(format_csv_row(&[
            r.id.to_string(),
            r.asset_group_id.to_string(),
            r.group_name,
            r.ip_addr,
            r.status,
            r.is_unstable.to_string(),
            r.is_probable_tarpit.to_string(),
            r.auto_tags.join(";"),
            r.manual_tags.join(";"),
            r.owner_hint.unwrap_or_default(),
            r.notes.unwrap_or_default(),
            r.first_seen_at.to_rfc3339(),
            r.last_seen_at.map(|d| d.to_rfc3339()).unwrap_or_default(),
        ]));
    }
    Ok(csv_response("asi-hosts.csv", lines.join("\n")))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/services.csv",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Services exported as CSV", content_type = "text/csv"),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn export_services_csv(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<(StatusCode, HeaderMap, String), AppError> {
    let instance = "/api/v1/export/services.csv";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    #[derive(sqlx::FromRow)]
    struct CsvServiceRow {
        asset_group_id: Uuid,
        group_name: String,
        host_id: Uuid,
        ip_addr: String,
        port: i32,
        protocol: String,
        state: String,
        service_name: Option<String>,
        product: Option<String>,
        version: Option<String>,
    }

    let rows: Vec<CsvServiceRow> = sqlx::query_as(
        r#"
        SELECT h.asset_group_id, ag.name AS group_name, hp.host_id, h.ip_addr::text AS ip_addr,
               hp.port, hp.protocol, hp.state, hp.service_name, hp.product, hp.version
        FROM host_ports hp
        JOIN hosts h ON h.id = hp.host_id
        JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
        ORDER BY ag.name ASC, h.ip_addr ASC, hp.port ASC
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "export services csv failed", auth.request_id, instance))?;

    let mut lines = vec![format_csv_row(&[
        "asset_group_id".into(),
        "asset_group_name".into(),
        "host_id".into(),
        "ip_addr".into(),
        "port".into(),
        "protocol".into(),
        "state".into(),
        "service_name".into(),
        "product".into(),
        "version".into(),
    ])];
    for r in rows {
        lines.push(format_csv_row(&[
            r.asset_group_id.to_string(),
            r.group_name,
            r.host_id.to_string(),
            r.ip_addr,
            r.port.to_string(),
            r.protocol,
            r.state,
            r.service_name.unwrap_or_default(),
            r.product.unwrap_or_default(),
            r.version.unwrap_or_default(),
        ]));
    }
    Ok(csv_response("asi-services.csv", lines.join("\n")))
}

#[utoipa::path(
    get,
    path = "/api/v1/export/diffs.csv",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    params(GroupScopeQuery),
    responses(
        (status = 200, description = "Diff events exported as CSV", content_type = "text/csv"),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn export_diffs_csv(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<GroupScopeQuery>,
) -> Result<(StatusCode, HeaderMap, String), AppError> {
    let instance = "/api/v1/export/diffs.csv";
    auth.require(Permission::ExportReports, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    #[derive(sqlx::FromRow)]
    struct CsvDiffRow {
        id: Uuid,
        asset_group_id: Uuid,
        group_name: String,
        host_id: Uuid,
        ip_addr: String,
        event_kind: String,
        severity: String,
        bullet_items: serde_json::Value,
        detected_at: DateTime<Utc>,
    }

    let rows: Vec<CsvDiffRow> = sqlx::query_as(
        r#"
        SELECT de.id, h.asset_group_id, ag.name AS group_name, de.host_id, h.ip_addr::text AS ip_addr,
               de.event_kind, de.severity, de.bullet_items, de.detected_at
        FROM diff_events de
        JOIN hosts h ON h.id = de.host_id
        JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
        ORDER BY de.detected_at DESC
        "#,
    )
    .bind(query.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "export diffs csv failed", auth.request_id, instance))?;

    let mut lines = vec![format_csv_row(&[
        "diff_id".into(),
        "asset_group_id".into(),
        "asset_group_name".into(),
        "host_id".into(),
        "ip_addr".into(),
        "event_kind".into(),
        "severity".into(),
        "bullet_items".into(),
        "detected_at".into(),
    ])];
    for r in rows {
        lines.push(format_csv_row(&[
            r.id.to_string(),
            r.asset_group_id.to_string(),
            r.group_name,
            r.host_id.to_string(),
            r.ip_addr,
            r.event_kind,
            r.severity,
            r.bullet_items.to_string(),
            r.detected_at.to_rfc3339(),
        ]));
    }
    Ok(csv_response("asi-diffs.csv", lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_escape_and_row_format_handle_special_chars() {
        let row = format_csv_row(&[
            "plain".to_string(),
            "hello, world".to_string(),
            "say \"hi\"".to_string(),
            "line1\nline2".to_string(),
        ]);
        assert_eq!(
            row,
            "plain,\"hello, world\",\"say \"\"hi\"\"\",\"line1\nline2\""
        );
    }

    #[test]
    fn flexible_targets_parser_handles_raw_csv_and_json() {
        let raw = parse_flexible_targets(
            Some("auto"),
            "10.0.0.1\n10.0.0.0/24\napp.example.com\n!10.0.0.128/25",
        )
        .expect("raw targets should parse");
        assert_eq!(raw.len(), 4);
        assert_eq!(raw[0].target_type, TargetType::Ip);
        assert_eq!(raw[1].target_type, TargetType::Cidr);
        assert_eq!(raw[2].target_type, TargetType::Domain);
        assert_eq!(raw[3].target_type, TargetType::ExcludeCidr);

        let csv =
            "target_type,value,notes\nip,192.168.1.10,db\ndomain,portal.local,\"main, portal\"\n";
        let parsed_csv = parse_flexible_targets(Some("auto"), csv).expect("csv should parse");
        assert_eq!(parsed_csv.len(), 2);
        assert_eq!(parsed_csv[1].notes.as_deref(), Some("main, portal"));

        let json_str = r#"["10.10.10.1", {"target_type": "domain", "value": "api.local"}]"#;
        let parsed_json =
            parse_flexible_targets(Some("auto"), json_str).expect("json should parse");
        assert_eq!(parsed_json.len(), 2);
        assert_eq!(parsed_json[0].target_type, TargetType::Ip);
        assert_eq!(parsed_json[1].target_type, TargetType::Domain);
    }

    #[test]
    fn scan_results_csv_parser_extracts_hosts_ports_and_web() {
        let csv = "\
ip_addr,port,protocol,service_name,vhost,http_status,title,technologies,detected_paths
10.0.0.5,443,tcp,https,admin.local,200,\"Admin Portal\",nginx;react,/admin|/login
10.0.0.6,22,tcp,ssh,,,,,
";
        let items =
            parse_scan_results_input(Some("auto"), Some(csv), &[]).expect("csv scan results");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].item.port, 443);
        assert_eq!(items[0].item.technologies, vec!["nginx", "react"]);
        assert_eq!(items[0].detected_paths, vec!["/admin", "/login"]);
        assert_eq!(items[1].item.port, 22);
        assert!(items[1].detected_paths.is_empty());
    }
}
