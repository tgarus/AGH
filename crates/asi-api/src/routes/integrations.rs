//! Endpointy integracji z DefectDojo (Faza 6, ADR-0008).
//! Zapis/odczyt konfiguracji, test polaczenia, reczny sync i push pojedynczych diffow.
//! Wszystkie akcje mutujace wymagaja permisji ManageExternalIntegrations (Admin).

use asi_common::defectdojo::{
    DdFindingPayloadOverride, DdFindingPreviewDto, DdFindingScope, DdLinkDto, DdOutboxItemDto,
    DdPushDiffResponse, DdPushHostResponse, DdRetryOutboxResponse, DdSyncRequest, DdSyncResponse,
    DdTestConnectionResponse, DefectDojoConfigDto, UpdateDefectDojoConfigRequest,
};
use asi_common::error::{DomainError, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use axum::body::Bytes;
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
use crate::integrations::push::{
    audit_dd, build_diff_dd_preview, build_host_dd_preview, enqueue_manual_sync, push_single_diff,
    push_single_host, save_diff_dd_override, save_host_dd_override,
};
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
                asi_public_url: r
                    .get::<Option<String>, _>("asi_public_url")
                    .unwrap_or_default(),
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
            asi_public_url: String::new(),
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
            last_error = NULL,
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
    request_body(content = Option<UpdateDefectDojoConfigRequest>, description = "Optional unsaved base_url / api_key values to test before saving"),
    responses(
        (status = 200, description = "Connection test result", body = DdTestConnectionResponse)
    )
)]
pub async fn test_defectdojo_connection(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<DdTestConnectionResponse>, AppError> {
    let instance = "/api/v1/integrations/defectdojo/test-connection";
    auth.require(Permission::ManageExternalIntegrations, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let body_override: Option<UpdateDefectDojoConfigRequest> = if body.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&body).map_err(|e| {
            AppError::new(
                DomainError::BadRequest(format!("Niepoprawny JSON żądania: {e}")),
                auth.request_id,
                Some(instance.to_string()),
            )
        })?)
    };

    let stored = sqlx::query(
        "SELECT base_url, api_key_ciphertext, api_key_nonce FROM defectdojo_config WHERE id = TRUE",
    )
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "dd config read failed", auth.request_id, instance))?;

    let (stored_url, stored_key) = match stored {
        Some(r) => {
            let u: String = r.get("base_url");
            let c: Option<Vec<u8>> = r.get("api_key_ciphertext");
            let n: Option<Vec<u8>> = r.get("api_key_nonce");
            let k = match (c, n) {
                (Some(ct), Some(nc)) => state
                    .secret_box
                    .decrypt(&ct, &nc)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .unwrap_or_default(),
                _ => String::new(),
            };
            (u, k)
        }
        None => (String::new(), String::new()),
    };

    let effective_url = body_override
        .as_ref()
        .and_then(|o| o.base_url.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or(stored_url);
    let effective_key = body_override
        .as_ref()
        .and_then(|o| o.api_key.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or(stored_key);

    if effective_url.trim().is_empty() || effective_key.trim().is_empty() {
        return Ok(Json(DdTestConnectionResponse {
            ok: false,
            base_url: effective_url,
            product_count: None,
            error: Some(
                "Brak Base URL lub API key (uzupełnij pola i zapisz albo podaj w formularzu)."
                    .to_string(),
            ),
        }));
    }

    let client = match DdClient::new(&effective_url, &effective_key) {
        Ok(c) => c,
        Err(e) => {
            return Ok(Json(DdTestConnectionResponse {
                ok: false,
                base_url: effective_url,
                product_count: None,
                error: Some(e.to_string()),
            }));
        }
    };

    match client.ping().await {
        Ok(count) => {
            let _ = sqlx::query(
                "UPDATE defectdojo_config SET last_error = NULL, updated_at = NOW() WHERE id = TRUE AND last_error IS NOT NULL",
            )
            .execute(pool)
            .await;
            Ok(Json(DdTestConnectionResponse {
                ok: true,
                base_url: effective_url,
                product_count: Some(count),
                error: None,
            }))
        }
        Err(e) => {
            let _ = sqlx::query(
                "UPDATE defectdojo_config SET last_error = $1, updated_at = NOW() WHERE id = TRUE",
            )
            .bind(&e)
            .execute(pool)
            .await;
            Ok(Json(DdTestConnectionResponse {
                ok: false,
                base_url: effective_url,
                product_count: None,
                error: Some(e),
            }))
        }
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

async fn read_asi_public_url(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(asi_public_url, '') FROM defectdojo_config WHERE id = TRUE",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_default()
}

fn parse_optional_override(
    bytes: &[u8],
    request_id: Option<Uuid>,
    instance: &str,
) -> Result<Option<DdFindingPayloadOverride>, AppError> {
    let trimmed = std::str::from_utf8(bytes)
        .map_err(|e| {
            AppError::new(
                DomainError::BadRequest(format!("invalid UTF-8 body: {e}")),
                request_id,
                Some(instance.to_string()),
            )
        })?
        .trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let ov: DdFindingPayloadOverride = serde_json::from_str(trimmed).map_err(|e| {
        AppError::new(
            DomainError::BadRequest(format!("invalid override JSON: {e}")),
            request_id,
            Some(instance.to_string()),
        )
    })?;
    Ok(Some(ov))
}

#[utoipa::path(
    get,
    path = "/api/v1/integrations/defectdojo/preview/diff/{diff_event_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("diff_event_id" = Uuid, Path, description = "ASI diff event UUID")),
    responses(
        (status = 200, description = "Preview of DefectDojo finding payload + saved override for diff event", body = DdFindingPreviewDto),
        (status = 404, description = "Diff not found", body = ProblemDetails)
    )
)]
pub async fn preview_diff_defectdojo(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(diff_event_id): Path<Uuid>,
) -> Result<Json<DdFindingPreviewDto>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/preview/diff/{diff_event_id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let asi_public_url = read_asi_public_url(pool).await;

    match build_diff_dd_preview(pool, &asi_public_url, diff_event_id).await {
        Ok(dto) => Ok(Json(dto)),
        Err(e) if e.contains("not found") => Err(AppError::new(
            DomainError::NotFound(e),
            auth.request_id,
            Some(instance),
        )),
        Err(e) => Err(AppError::new(
            DomainError::BadRequest(e),
            auth.request_id,
            Some(instance),
        )),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/integrations/defectdojo/override/diff/{diff_event_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("diff_event_id" = Uuid, Path, description = "ASI diff event UUID")),
    request_body = DdFindingPayloadOverride,
    responses(
        (status = 200, description = "Saved DefectDojo payload override for diff event", body = DdFindingPreviewDto),
        (status = 404, description = "Diff not found", body = ProblemDetails)
    )
)]
pub async fn save_diff_defectdojo_override(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(diff_event_id): Path<Uuid>,
    Json(payload): Json<DdFindingPayloadOverride>,
) -> Result<Json<DdFindingPreviewDto>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/override/diff/{diff_event_id}");
    auth.require(Permission::ManageExternalIntegrations, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    if let Err(e) = save_diff_dd_override(pool, diff_event_id, &payload).await {
        if e.contains("not found") {
            return Err(AppError::new(
                DomainError::NotFound(e),
                auth.request_id,
                Some(instance),
            ));
        }
        return Err(AppError::new(
            DomainError::BadRequest(e),
            auth.request_id,
            Some(instance),
        ));
    }

    let asi_public_url = read_asi_public_url(pool).await;
    let preview = build_diff_dd_preview(pool, &asi_public_url, diff_event_id)
        .await
        .map_err(|e| AppError::new(DomainError::BadRequest(e), auth.request_id, Some(instance)))?;
    Ok(Json(preview))
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/defectdojo/push/{diff_event_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("diff_event_id" = Uuid, Path, description = "ASI diff event UUID")),
    request_body(content = Option<DdFindingPayloadOverride>, description = "Optional DefectDojo finding payload override applied before pushing"),
    responses(
        (status = 200, description = "Diff pushed (or updated) to DefectDojo", body = DdPushDiffResponse),
        (status = 404, description = "Diff not found", body = ProblemDetails)
    )
)]
pub async fn push_diff_to_defectdojo(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(diff_event_id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<DdPushDiffResponse>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/push/{diff_event_id}");
    auth.require(Permission::ManageExternalIntegrations, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let override_opt = parse_optional_override(&body, auth.request_id, &instance)?;

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

    match push_single_diff(pool, &state.secret_box, diff_event_id, override_opt).await {
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
    path = "/api/v1/integrations/defectdojo/preview/host/{host_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("host_id" = Uuid, Path, description = "ASI host UUID")),
    responses(
        (status = 200, description = "Preview of DefectDojo finding payload + saved override for host", body = DdFindingPreviewDto),
        (status = 404, description = "Host not found", body = ProblemDetails)
    )
)]
pub async fn preview_host_defectdojo(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
) -> Result<Json<DdFindingPreviewDto>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/preview/host/{host_id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let asi_public_url = read_asi_public_url(pool).await;

    match build_host_dd_preview(pool, &asi_public_url, host_id).await {
        Ok(dto) => Ok(Json(dto)),
        Err(e) if e.contains("not found") => Err(AppError::new(
            DomainError::NotFound(e),
            auth.request_id,
            Some(instance),
        )),
        Err(e) => Err(AppError::new(
            DomainError::BadRequest(e),
            auth.request_id,
            Some(instance),
        )),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/integrations/defectdojo/override/host/{host_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("host_id" = Uuid, Path, description = "ASI host UUID")),
    request_body = DdFindingPayloadOverride,
    responses(
        (status = 200, description = "Saved DefectDojo payload override for host", body = DdFindingPreviewDto),
        (status = 404, description = "Host not found", body = ProblemDetails)
    )
)]
pub async fn save_host_defectdojo_override(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    Json(payload): Json<DdFindingPayloadOverride>,
) -> Result<Json<DdFindingPreviewDto>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/override/host/{host_id}");
    auth.require(Permission::ManageExternalIntegrations, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    if let Err(e) = save_host_dd_override(pool, host_id, &payload).await {
        if e.contains("not found") {
            return Err(AppError::new(
                DomainError::NotFound(e),
                auth.request_id,
                Some(instance),
            ));
        }
        return Err(AppError::new(
            DomainError::BadRequest(e),
            auth.request_id,
            Some(instance),
        ));
    }

    let asi_public_url = read_asi_public_url(pool).await;
    let preview = build_host_dd_preview(pool, &asi_public_url, host_id)
        .await
        .map_err(|e| AppError::new(DomainError::BadRequest(e), auth.request_id, Some(instance)))?;
    Ok(Json(preview))
}

#[utoipa::path(
    post,
    path = "/api/v1/integrations/defectdojo/push-host/{host_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("host_id" = Uuid, Path, description = "ASI host UUID")),
    request_body(content = Option<DdFindingPayloadOverride>, description = "Optional DefectDojo finding payload override applied before pushing host"),
    responses(
        (status = 200, description = "Host pushed (or updated) to DefectDojo", body = DdPushHostResponse),
        (status = 404, description = "Host not found", body = ProblemDetails)
    )
)]
pub async fn push_host_to_defectdojo(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<DdPushHostResponse>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/push-host/{host_id}");
    auth.require(Permission::ManageExternalIntegrations, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let override_opt = parse_optional_override(&body, auth.request_id, &instance)?;

    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM hosts WHERE id = $1")
        .bind(host_id)
        .fetch_optional(pool)
        .await
        .map_err(|err| map_db_err(err, "host lookup failed", auth.request_id, &instance))?;
    if exists.is_none() {
        return Err(AppError::new(
            DomainError::NotFound(format!("host {host_id} not found")),
            auth.request_id,
            Some(instance),
        ));
    }

    match push_single_host(pool, &state.secret_box, host_id, override_opt).await {
        Ok(dd_finding_id) => Ok(Json(DdPushHostResponse {
            host_id,
            dd_finding_id,
            note: format!("pushed host to DefectDojo as finding #{dd_finding_id}"),
        })),
        Err(e) => Err(AppError::new(
            DomainError::BadRequest(format!("host push failed: {e}")),
            auth.request_id,
            Some(instance),
        )),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/integrations/defectdojo/host-link/{host_id}",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    params(("host_id" = Uuid, Path, description = "ASI host UUID")),
    responses(
        (status = 200, description = "DefectDojo link for host", body = DdLinkDto),
        (status = 404, description = "No host link yet", body = ProblemDetails)
    )
)]
pub async fn get_dd_host_link(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(host_id): Path<Uuid>,
) -> Result<Json<DdLinkDto>, AppError> {
    let instance = format!("/api/v1/integrations/defectdojo/host-link/{host_id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let row = sqlx::query(
        r#"SELECT dd_product_id, dd_engagement_id, dd_test_id, dd_finding_id,
                  dd_finding_status, dd_tags, last_pushed_at, last_pulled_at
           FROM dd_links
           WHERE host_id = $1 AND diff_event_id IS NULL"#,
    )
    .bind(host_id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "dd host link read failed", auth.request_id, &instance))?
    .ok_or_else(|| {
        AppError::new(
            DomainError::NotFound(format!("no DefectDojo link for host {host_id}")),
            auth.request_id,
            Some(instance.clone()),
        )
    })?;

    let tags: Vec<String> = serde_json::from_value(row.get("dd_tags")).unwrap_or_default();
    Ok(Json(DdLinkDto {
        diff_event_id: host_id,
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

#[utoipa::path(
    post,
    path = "/api/v1/integrations/defectdojo/outbox/retry",
    tag = "Integrations",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Reset failed outbox entries to pending and clear last_error", body = DdRetryOutboxResponse)
    )
)]
pub async fn retry_failed_dd_outbox(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<DdRetryOutboxResponse>, AppError> {
    let instance = "/api/v1/integrations/defectdojo/outbox/retry";
    auth.require(Permission::ManageExternalIntegrations, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let res = sqlx::query(
        r#"
        UPDATE dd_outbox
        SET status = 'pending',
            next_retry_at = NOW(),
            last_error = NULL,
            updated_at = NOW()
        WHERE status IN ('failed', 'pending')
        "#,
    )
    .execute(pool)
    .await
    .map_err(|err| map_db_err(err, "outbox retry failed", auth.request_id, instance))?;

    let _ = sqlx::query(
        "UPDATE defectdojo_config SET last_error = NULL, updated_at = NOW() WHERE id = TRUE",
    )
    .execute(pool)
    .await;

    Ok(Json(DdRetryOutboxResponse {
        retried_count: i64::try_from(res.rows_affected()).unwrap_or(0),
    }))
}
