//! Endpointy integracji z DefectDojo (Faza 6, ADR-0008).
//! Zapis/odczyt konfiguracji, test polaczenia, reczny sync i push pojedynczych diffow.
//! Wszystkie akcje mutujace wymagaja permisji ManageExternalIntegrations (Admin).

use asi_common::defectdojo::{
    DdFindingScope, DdLinkDto, DdOutboxItemDto, DdPushDiffResponse, DdSyncRequest, DdSyncResponse,
    DdTestConnectionResponse, DefectDojoConfigDto, UpdateDefectDojoConfigRequest,
};
use asi_common::error::{DomainError, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use sqlx::Row;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::integrations::defectdojo::DdClient;
use crate::integrations::push::{audit_dd, enqueue_manual_sync, load_config, push_single_diff};
use crate::routes::common::{extract_request_id, map_db_err, require_db};
use crate::security::auth_extractor::AuthenticatedUser;

fn validation(msg: String, field: &str) -> AppError {
    AppError::new(
        DomainError::Validation {
            detail: msg.clone(),
            violations: vec![asi_common::error::FieldViolation {
                field: field.to_string(),
                code: "invalid".to_string(),
                message: msg,
            }],
        },
        None,
        None,
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/integrations/defectdojo",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "DefectDojo integration config (API key redacted) + status", body = DefectDojoConfigDto)
    )
)]
pub async fn get_defectdojo_config(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<DefectDojoConfigDto>, AppError> {
    let instance = "/api/v1/integrations/defectdojo";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let row = sqlx::query(
        r#"SELECT base_url, asi_public_url, api_key_ciphertext IS NOT NULL AS has_api_key,
                  finding_scope, auto_push, pull_interval_minutes, enabled,
                  last_push_at, last_pull_at, last_error, updated_at
           FROM defectdojo_config WHERE id = TRUE"#,
    )
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "dd config read failed", auth.request_id, instance))?;

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dd_outbox WHERE status IN ('pending','processing','failed')",
    )
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "dd outbox count failed", auth.request_id, instance))?;

    let dto = match row {
        Some(r) => {
            let scope_raw: String = r.get("finding_scope");
            DefectDojoConfigDto {
                base_url: r.get("base_url"),
                finding_scope: DdFindingScope::from_db_str(&scope_raw)
                    .unwrap_or(DdFindingScope::Changes),
                auto_push: r.get("auto_push"),
                pull_interval_minutes: r.get("pull_interval_minutes"),
                enabled: r.get("enabled"),
                has_api_key: r.get("has_api_key"),
                pending_outbox: pending,
                last_push_at: r.get("last_push_at"),
                last_pull_at: r.get("last_pull_at"),
                last_error: r.get("last_error"),
                updated_at: r.get("updated_at"),
            }
        }
        None => DefectDojoConfigDto {
            base_url: String::new(),
            finding_scope: DdFindingScope::Changes,
            auto_push: true,
            pull_interval_minutes: 15,
            enabled: false,
            has_api_key: false,
            pending_outbox: pending,
            last_push_at: None,
            last_pull_at: None,
            last_error: None,
            updated_at: Utc::now(),
        },
    };
    Ok(Json(dto))
}

#[utoipa::path(
    put,
    path = "/api/v1/integrations/defectdojo",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    request_body = UpdateDefectDojoConfigRequest,
    responses(
        (status = 200, description = "DefectDojo integration config saved", body = DefectDojoConfigDto),
        (status = 400, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn update_defectdojo_config(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<UpdateDefectDojoConfigRequest>,
) -> Result<Json<DefectDojoConfigDto>, AppError> {
    let instance = "/api/v1/integrations/defectdojo";
    auth.require(Permission::ManageExternalIntegrations, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let base_url = payload
        .base_url
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_default();
    if base_url.is_empty() && payload.enabled == Some(true) {
        return Err(validation(
            "base_url is required when enabling the integration".to_string(),
            "base_url",
        ));
    }
    if !base_url.is_empty() && reqwest::Url::parse(&base_url).is_err() {
        return Err(validation(
            "base_url must be a valid http(s) URL".to_string(),
            "base_url",
        ));
    }
    if let Some(min) = payload.pull_interval_minutes {
        if !(1..=1440).contains(&min) {
            return Err(validation(
                "pull_interval_minutes must be between 1 and 1440".to_string(),
                "pull_interval_minutes",
            ));
        }
    }
    if let Some(scope) = payload.finding_scope {
        let _ = scope; // enum juz walidowany przez serde
    }

    let (cipher, nonce) = match payload
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(key) => {
            let (c, n) = state.secret_box.encrypt(key.as_bytes()).map_err(|e| {
                AppError::new(
                    DomainError::Internal(e.to_string()),
                    auth.request_id,
                    Some(instance.to_string()),
                )
            })?;
            (Some(c), Some(n))
        }
        None => (None, None),
    };

    sqlx::query(
        r#"
        INSERT INTO defectdojo_config (id, base_url, asi_public_url, api_key_ciphertext, api_key_nonce,
                                       finding_scope, auto_push, pull_interval_minutes, enabled)
        VALUES (TRUE,
                COALESCE($1, ''), COALESCE($8, ''),
                $2, $3,
                COALESCE($4, 'changes'),
                COALESCE($5, TRUE),
                COALESCE($6, 15),
                COALESCE($7, FALSE))
        ON CONFLICT (id) DO UPDATE SET
            base_url = CASE WHEN $1 IS NOT NULL AND $1 <> '' THEN $1 ELSE defectdojo_config.base_url END,
            asi_public_url = COALESCE($8, defectdojo_config.asi_public_url),
            api_key_ciphertext = COALESCE($2, defectdojo_config.api_key_ciphertext),
            api_key_nonce = COALESCE($3, defectdojo_config.api_key_nonce),
            finding_scope = COALESCE($4, defectdojo_config.finding_scope),
            auto_push = COALESCE($5, defectdojo_config.auto_push),
            pull_interval_minutes = COALESCE($6, defectdojo_config.pull_interval_minutes),
            enabled = COALESCE($7, defectdojo_config.enabled),
            updated_at = NOW()
        "#,
    )
    .bind(payload.base_url.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(cipher)
    .bind(nonce)
    .bind(payload.finding_scope.map(|s| s.as_db_str().to_string()))
    .bind(payload.auto_push)
    .bind(payload.pull_interval_minutes)
    .bind(payload.enabled)
    .bind(payload.asi_public_url.as_deref().map(str::trim))
    .execute(pool)
    .await
    .map_err(|err| map_db_err(err, "dd config upsert failed", auth.request_id, instance))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "audit tx failed", auth.request_id, instance))?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "defectdojo.config_updated",
            resource_type: "defectdojo_integration",
            resource_id: None,
            before_state: None,
            after_state: Some(serde_json::json!({
                "enabled": payload.enabled,
                "auto_push": payload.auto_push,
                "finding_scope": payload.finding_scope,
                "pull_interval_minutes": payload.pull_interval_minutes,
                "base_url": payload.base_url,
                "api_key_changed": payload.api_key.is_some(),
            })),
            source_ip: crate::routes::common::extract_source_ip(&headers),
            request_id: auth.request_id.or_else(|| extract_request_id(&headers)),
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit insert failed", auth.request_id, instance))?;
    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, instance))?;

    audit_dd(
        pool,
        "defectdojo.config_updated",
        serde_json::json!({"by": auth.user.username}),
    )
    .await
    .map_err(|e| {
        AppError::new(
            DomainError::Internal(e),
            auth.request_id,
            Some(instance.to_string()),
        )
    })?;

    get_defectdojo_config(auth, State(state)).await
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/defectdojo/test-connection",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Connection test result", body = DdTestConnectionResponse)
    )
)]
pub async fn test_defectdojo_connection(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<DdTestConnectionResponse>, AppError> {
    let instance = "/api/v1/integrations/defectdojo/test-connection";
    auth.require(Permission::ManageExternalIntegrations, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let Some(cfg) = load_config(pool, &state.secret_box).await.map_err(|e| {
        AppError::new(
            DomainError::Internal(e),
            auth.request_id,
            Some(instance.to_string()),
        )
    })?
    else {
        return Ok(Json(DdTestConnectionResponse {
            ok: false,
            base_url: String::new(),
            product_count: None,
            error: Some("DefectDojo integration is disabled or API key is missing".to_string()),
        }));
    };
    let client = DdClient::new(&cfg.base_url, &cfg.api_key).map_err(|e| {
        AppError::new(
            DomainError::BadRequest(e.to_string()),
            auth.request_id,
            Some(instance.to_string()),
        )
    })?;
    match client.ping().await {
        Ok(count) => Ok(Json(DdTestConnectionResponse {
            ok: true,
            base_url: cfg.base_url,
            product_count: Some(count),
            error: None,
        })),
        Err(e) => Ok(Json(DdTestConnectionResponse {
            ok: false,
            base_url: cfg.base_url,
            product_count: None,
            error: Some(e.to_string()),
        })),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/defectdojo/sync",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    request_body = DdSyncRequest,
    responses(
        (status = 202, description = "Sync enqueued to outbox", body = DdSyncResponse)
    )
)]
pub async fn sync_defectdojo(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Json(payload): Json<DdSyncRequest>,
) -> Result<(StatusCode, Json<DdSyncResponse>), AppError> {
    let instance = "/api/v1/integrations/defectdojo/sync";
    auth.require(Permission::ManageExternalIntegrations, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let enqueued = enqueue_manual_sync(pool, payload.asset_group_id)
        .await
        .map_err(|e| {
            AppError::new(
                DomainError::Internal(e),
                auth.request_id,
                Some(instance.to_string()),
            )
        })?;
    Ok((StatusCode::ACCEPTED, Json(DdSyncResponse { enqueued })))
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/defectdojo/push/{diff_event_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("diff_event_id" = Uuid, Path, description = "ASI diff event UUID")),
    responses(
        (status = 200, description = "Diff pushed (or updated) to DefectDojo", body = DdPushDiffResponse),
        (status = 404, description = "Diff not found", body = ProblemDetails)
    )
)]
pub async fn push_diff_to_defectdojo(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(diff_event_id): Path<Uuid>,
) -> Result<Json<DdPushDiffResponse>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/push/{diff_event_id}");
    auth.require(Permission::ManageExternalIntegrations, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM diff_events WHERE id = $1")
        .bind(diff_event_id)
        .fetch_optional(pool)
        .await
        .map_err(|err| map_db_err(err, "diff lookup failed", auth.request_id, &instance))?;
    if exists.is_none() {
        return Err(AppError::new(
            DomainError::NotFound(format!("diff_event {diff_event_id} not found")),
            auth.request_id,
            Some(instance),
        ));
    }

    match push_single_diff(pool, &state.secret_box, diff_event_id).await {
        Ok(finding_id) => Ok(Json(DdPushDiffResponse {
            diff_event_id,
            enqueued: true,
            note: format!("pushed to DefectDojo as finding #{finding_id}"),
        })),
        Err(e) => Err(AppError::new(
            DomainError::BadRequest(format!("push failed: {e}")),
            auth.request_id,
            Some(instance),
        )),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/integrations/defectdojo/link/{diff_event_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("diff_event_id" = Uuid, Path, description = "ASI diff event UUID")),
    responses(
        (status = 200, description = "DefectDojo link for diff event", body = DdLinkDto),
        (status = 404, description = "No link yet", body = ProblemDetails)
    )
)]
pub async fn get_dd_link(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(diff_event_id): Path<Uuid>,
) -> Result<Json<DdLinkDto>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/link/{diff_event_id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let row = sqlx::query(
        r#"SELECT diff_event_id, dd_product_id, dd_engagement_id, dd_test_id, dd_finding_id,
                  dd_finding_status, dd_tags, last_pushed_at, last_pulled_at
           FROM dd_links WHERE diff_event_id = $1"#,
    )
    .bind(diff_event_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "dd link read failed", auth.request_id, &instance))?
    .ok_or_else(|| {
        AppError::new(
            DomainError::NotFound(format!("no DefectDojo link for diff {diff_event_id}")),
            auth.request_id,
            Some(instance.clone()),
        )
    })?;

    let tags: Vec<String> = serde_json::from_value(row.get("dd_tags")).unwrap_or_default();
    Ok(Json(DdLinkDto {
        diff_event_id: row.get("diff_event_id"),
        dd_product_id: row.get("dd_product_id"),
        dd_engagement_id: row.get("dd_engagement_id"),
        dd_test_id: row.get("dd_test_id"),
        dd_finding_id: row.get("dd_finding_id"),
        dd_finding_status: row.get("dd_finding_status"),
        dd_tags: tags,
        last_pushed_at: row.get("last_pushed_at"),
        last_pulled_at: row.get("last_pulled_at"),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/integrations/defectdojo/outbox",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated DefectDojo outbox", body = PaginatedResponse<DdOutboxItemDto>)
    )
)]
pub async fn list_dd_outbox(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<DdOutboxItemDto>>, AppError> {
    let instance = "/api/v1/integrations/defectdojo/outbox";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dd_outbox")
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "outbox count failed", auth.request_id, instance))?;

    let rows = sqlx::query(
        r#"SELECT id, kind, asset_group_id, scan_run_id, diff_event_id, status, attempt_count,
                  next_retry_at, last_error, created_at
           FROM dd_outbox ORDER BY created_at DESC LIMIT $1 OFFSET $2"#,
    )
    .bind(i64::from(per_page))
    .bind(i64::from(offset))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "outbox list failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|r| DdOutboxItemDto {
            id: r.get("id"),
            kind: r.get("kind"),
            asset_group_id: r.get("asset_group_id"),
            scan_run_id: r.get("scan_run_id"),
            diff_event_id: r.get("diff_event_id"),
            status: r.get("status"),
            attempt_count: r.get("attempt_count"),
            next_retry_at: r.get("next_retry_at"),
            last_error: r.get("last_error"),
            created_at: r.get("created_at"),
        })
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(page, per_page, u64::try_from(total).unwrap_or(0)),
    }))
}
