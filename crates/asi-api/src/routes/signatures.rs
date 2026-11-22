use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::io::EXPORT_SCHEMA_VERSION;
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use asi_common::signatures::{
    builtin_default_signatures_yaml, parse_fingerprinthub_v4_yaml, CreateSignatureRuleRequest,
    ImportSignaturesJsonRequest, ImportSignaturesJsonResponse, SignatureRuleDto,
    SignatureRuleSource, SyncSignaturesResponse, UpdateSignatureRuleRequest,
    ValidateSignatureRequest, ValidateSignatureResponse,
};
use asi_common::worker::WorkerControlEvent;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::routes::common::{extract_source_ip, map_db_err, require_db};
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct SignatureFilterQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub source: Option<SignatureRuleSource>,
    pub is_enabled: Option<bool>,
    pub q: Option<String>,
}

#[derive(FromRow)]
struct SignatureRuleRow {
    id: Uuid,
    template_id: String,
    name: String,
    source: String,
    format: String,
    yaml_content: String,
    content_sha256: String,
    tags: Vec<String>,
    is_enabled: bool,
    created_by: Option<Uuid>,
    synced_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl SignatureRuleRow {
    fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<SignatureRuleDto, AppError> {
        let source = SignatureRuleSource::from_db_str(&self.source).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid signature source '{}'", self.source)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(SignatureRuleDto {
            id: self.id,
            template_id: self.template_id,
            name: self.name,
            source,
            format: self.format,
            yaml_content: self.yaml_content,
            content_sha256: self.content_sha256,
            tags: self.tags,
            is_enabled: self.is_enabled,
            created_by: self.created_by,
            synced_at: self.synced_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn sha256_hex(content: &str) -> String {
    hex::encode(Sha256::digest(content.as_bytes()))
}

fn broadcast_signature_reload(state: &AppState) {
    state.events.emit_worker_control(WorkerControlEvent {
        action: "reload_signatures".to_string(),
        scan_run_id: None,
        chunk_id: None,
        grace_seconds: None,
    });
}

#[utoipa::path(
    get,
    path = "/api/v1/signatures",
    tag = "Signatures",
    security(("bearer_auth" = [])),
    params(SignatureFilterQuery),
    responses(
        (status = 200, description = "Paginated FingerprintHub v4 YAML signature rules", body = PaginatedResponse<SignatureRuleDto>)
    )
)]
pub async fn list_signatures(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<SignatureFilterQuery>,
) -> Result<Json<PaginatedResponse<SignatureRuleDto>>, AppError> {
    let instance = "/api/v1/signatures";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let pg = PaginationQuery {
        page: filter.page,
        per_page: filter.per_page,
        ..Default::default()
    }
    .sanitized();

    let source_filter = filter.source.map(|s| s.as_db_str().to_string());
    let search = filter
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("%{s}%"));

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM signature_rules
        WHERE ($1::text IS NULL OR source = $1)
          AND ($2::bool IS NULL OR is_enabled = $2)
          AND ($3::text IS NULL OR template_id ILIKE $3 OR name ILIKE $3)
        "#,
    )
    .bind(&source_filter)
    .bind(filter.is_enabled)
    .bind(&search)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "signatures count failed", auth.request_id, instance))?;

    let rows: Vec<SignatureRuleRow> = sqlx::query_as(
        r#"
        SELECT id, template_id, name, source, format, yaml_content, content_sha256,
               tags, is_enabled, created_by, synced_at, created_at, updated_at
        FROM signature_rules
        WHERE ($1::text IS NULL OR source = $1)
          AND ($2::bool IS NULL OR is_enabled = $2)
          AND ($3::text IS NULL OR template_id ILIKE $3 OR name ILIKE $3)
        ORDER BY template_id ASC
        LIMIT $4 OFFSET $5
        "#,
    )
    .bind(&source_filter)
    .bind(filter.is_enabled)
    .bind(&search)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "signatures query failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|r| r.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(
            pg.page,
            pg.per_page,
            u64::try_from(total.max(0)).unwrap_or(0),
        ),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/signatures/{id}",
    tag = "Signatures",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Signature rule UUID")),
    responses(
        (status = 200, description = "Signature rule details", body = SignatureRuleDto),
        (status = 404, description = "Signature rule not found", body = ProblemDetails)
    )
)]
pub async fn get_signature(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SignatureRuleDto>, AppError> {
    let instance = format!("/api/v1/signatures/{id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let row: Option<SignatureRuleRow> = sqlx::query_as(
        r#"
        SELECT id, template_id, name, source, format, yaml_content, content_sha256,
               tags, is_enabled, created_by, synced_at, created_at, updated_at
        FROM signature_rules
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "signature lookup failed", auth.request_id, &instance))?;

    let Some(row) = row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Signature rule {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    Ok(Json(row.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/signatures/validate",
    tag = "Signatures",
    security(("bearer_auth" = [])),
    request_body = ValidateSignatureRequest,
    responses(
        (status = 200, description = "FingerprintHub v4 YAML validation summary", body = ValidateSignatureResponse)
    )
)]
pub async fn validate_signature(
    auth: AuthenticatedUser,
    Json(payload): Json<ValidateSignatureRequest>,
) -> Result<Json<ValidateSignatureResponse>, AppError> {
    let instance = "/api/v1/signatures/validate";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;

    match parse_fingerprinthub_v4_yaml(&payload.yaml_content) {
        Ok(tpl) => Ok(Json(ValidateSignatureResponse {
            valid: true,
            template_id: Some(tpl.id),
            name: Some(tpl.info.name),
            tags: tpl.info.tags,
            error: None,
        })),
        Err(err) => Ok(Json(ValidateSignatureResponse {
            valid: false,
            template_id: None,
            name: None,
            tags: Vec::new(),
            error: Some(err),
        })),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/signatures",
    tag = "Signatures",
    security(("bearer_auth" = [])),
    request_body = CreateSignatureRuleRequest,
    responses(
        (status = 201, description = "Created custom FingerprintHub v4 signature rule", body = SignatureRuleDto),
        (status = 409, description = "Duplicate template_id", body = ProblemDetails),
        (status = 422, description = "Invalid YAML template", body = ProblemDetails)
    )
)]
pub async fn create_signature(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateSignatureRuleRequest>,
) -> Result<(StatusCode, Json<SignatureRuleDto>), AppError> {
    let instance = "/api/v1/signatures";
    auth.require(Permission::ManageCustomSignatures, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let tpl = parse_fingerprinthub_v4_yaml(&payload.yaml_content).map_err(|msg| {
        AppError::new(
            DomainError::Validation {
                detail: "Signature YAML validation failed.".to_string(),
                violations: vec![FieldViolation {
                    field: "yaml_content".to_string(),
                    code: "INVALID_FINGERPRINTHUB_YAML".to_string(),
                    message: msg,
                }],
            },
            auth.request_id,
            Some(instance.to_string()),
        )
    })?;

    let sha256 = sha256_hex(&payload.yaml_content);
    let is_enabled = payload.is_enabled.unwrap_or(true);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, instance))?;

    let row: SignatureRuleRow = sqlx::query_as(
        r#"
        INSERT INTO signature_rules (
            template_id, name, source, format, yaml_content, content_sha256,
            tags, is_enabled, created_by
        )
        VALUES ($1, $2, 'custom', 'fingerprinthub_v4_yaml', $3, $4, $5, $6, $7)
        RETURNING id, template_id, name, source, format, yaml_content, content_sha256,
                  tags, is_enabled, created_by, synced_at, created_at, updated_at
        "#,
    )
    .bind(&tpl.id)
    .bind(&tpl.info.name)
    .bind(&payload.yaml_content)
    .bind(&sha256)
    .bind(&tpl.info.tags)
    .bind(is_enabled)
    .bind(auth.user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "Signature with this template_id already exists.",
            auth.request_id,
            instance,
        )
    })?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "signature_rule.created",
            resource_type: "signature_rule",
            resource_id: Some(row.id),
            before_state: None,
            after_state: Some(serde_json::json!({ "template_id": row.template_id })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, instance))?;

    broadcast_signature_reload(&state);
    Ok((
        StatusCode::CREATED,
        Json(row.into_dto(auth.request_id, instance)?),
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/signatures/{id}",
    tag = "Signatures",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Signature rule UUID")),
    request_body = UpdateSignatureRuleRequest,
    responses(
        (status = 200, description = "Updated signature rule", body = SignatureRuleDto),
        (status = 404, description = "Signature rule not found", body = ProblemDetails),
        (status = 422, description = "Invalid YAML template", body = ProblemDetails)
    )
)]
pub async fn update_signature(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateSignatureRuleRequest>,
) -> Result<Json<SignatureRuleDto>, AppError> {
    let instance = format!("/api/v1/signatures/{id}");
    auth.require(Permission::ManageCustomSignatures, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let parsed = if let Some(ref yaml) = payload.yaml_content {
        let tpl = parse_fingerprinthub_v4_yaml(yaml).map_err(|msg| {
            AppError::new(
                DomainError::Validation {
                    detail: "Signature YAML validation failed.".to_string(),
                    violations: vec![FieldViolation {
                        field: "yaml_content".to_string(),
                        code: "INVALID_FINGERPRINTHUB_YAML".to_string(),
                        message: msg,
                    }],
                },
                auth.request_id,
                Some(instance.clone()),
            )
        })?;
        Some((tpl, sha256_hex(yaml)))
    } else {
        None
    };

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, &instance))?;

    let current: Option<SignatureRuleRow> = sqlx::query_as(
        r#"
        SELECT id, template_id, name, source, format, yaml_content, content_sha256,
               tags, is_enabled, created_by, synced_at, created_at, updated_at
        FROM signature_rules
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "signature lookup failed", auth.request_id, &instance))?;

    let Some(current) = current else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Signature rule {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let (next_template_id, next_name, next_yaml, next_sha, next_tags) = match parsed {
        Some((tpl, sha)) => (
            tpl.id,
            tpl.info.name,
            payload.yaml_content.unwrap_or(current.yaml_content),
            sha,
            tpl.info.tags,
        ),
        None => (
            current.template_id,
            current.name,
            current.yaml_content,
            current.content_sha256,
            current.tags,
        ),
    };
    let next_enabled = payload.is_enabled.unwrap_or(current.is_enabled);

    let updated: SignatureRuleRow = sqlx::query_as(
        r#"
        UPDATE signature_rules
        SET template_id = $1,
            name = $2,
            yaml_content = $3,
            content_sha256 = $4,
            tags = $5,
            is_enabled = $6,
            updated_at = NOW()
        WHERE id = $7
        RETURNING id, template_id, name, source, format, yaml_content, content_sha256,
                  tags, is_enabled, created_by, synced_at, created_at, updated_at
        "#,
    )
    .bind(&next_template_id)
    .bind(&next_name)
    .bind(&next_yaml)
    .bind(&next_sha)
    .bind(&next_tags)
    .bind(next_enabled)
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "signature update failed", auth.request_id, &instance))?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "signature_rule.updated",
            resource_type: "signature_rule",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "template_id": updated.template_id,
                "is_enabled": updated.is_enabled,
            })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    broadcast_signature_reload(&state);
    Ok(Json(updated.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    delete,
    path = "/api/v1/signatures/{id}",
    tag = "Signatures",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Signature rule UUID")),
    responses(
        (status = 204, description = "Signature rule deleted"),
        (status = 404, description = "Signature rule not found", body = ProblemDetails)
    )
)]
pub async fn delete_signature(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/signatures/{id}");
    auth.require(Permission::ManageCustomSignatures, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, &instance))?;

    let deleted: Option<String> =
        sqlx::query_scalar("DELETE FROM signature_rules WHERE id = $1 RETURNING template_id")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| {
                map_db_err(err, "signature delete failed", auth.request_id, &instance)
            })?;

    let Some(template_id) = deleted else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Signature rule {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "signature_rule.deleted",
            resource_type: "signature_rule",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({ "template_id": template_id })),
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

    broadcast_signature_reload(&state);
    Ok(StatusCode::NO_CONTENT)
}

/// Rdzeń synchronizacji sygnatur: wbudowane + repo FingerprintHub (GitHub tarball
/// lub lokalny katalog). Wspólne dla endpointu HTTP i syncu przy starcie.
///
/// Reguły `source = 'custom'` (z UI/importu) są chronione — nigdy nie są nadpisywane.
pub async fn run_signature_sync(
    pool: &sqlx::PgPool,
    sig_cfg: &crate::config::SignatureSyncConfig,
    actor: Option<Uuid>,
    source_ip: Option<ipnetwork::IpNetwork>,
    request_id: Option<Uuid>,
) -> Result<SyncSignaturesResponse, AppError> {
    let instance = "/api/v1/signatures/sync";
    let now = Utc::now();

    let (repo_yamls, repo_error) = match crate::signatures_repo::load_repo_yaml_files(sig_cfg).await
    {
        Ok(files) => {
            tracing::info!(count = files.len(), "FingerprintHub repo files loaded");
            (files, None)
        }
        Err(err) => {
            tracing::warn!(error = %err, "FingerprintHub repo load failed; syncing built-ins only");
            (Vec::new(), Some(err))
        }
    };
    let source = if let Some(dir) = &sig_cfg.local_dir {
        format!("builtin+local:{dir}")
    } else {
        format!("builtin+github:{}@{}", sig_cfg.repo, sig_cfg.git_ref)
    };
    let source = if repo_error.is_some() {
        "builtin (repo sync failed)".to_string()
    } else {
        source
    };

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", request_id, instance))?;

    let mut builtin_count = 0_usize;
    for yaml in builtin_default_signatures_yaml() {
        let Ok(tpl) = parse_fingerprinthub_v4_yaml(&yaml) else {
            continue;
        };
        let sha = sha256_hex(&yaml);
        sqlx::query(
            r#"
            INSERT INTO signature_rules (
                template_id, name, source, format, yaml_content, content_sha256,
                tags, is_enabled, created_by, synced_at
            )
            VALUES ($1, $2, 'fingerprinthub', 'fingerprinthub_v4_yaml', $3, $4, $5, TRUE, $6, $7)
            ON CONFLICT (template_id) DO UPDATE
            SET name = EXCLUDED.name,
                yaml_content = EXCLUDED.yaml_content,
                content_sha256 = EXCLUDED.content_sha256,
                tags = EXCLUDED.tags,
                synced_at = EXCLUDED.synced_at,
                updated_at = NOW()
            WHERE signature_rules.source <> 'custom'
            "#,
        )
        .bind(&tpl.id)
        .bind(&tpl.info.name)
        .bind(&yaml)
        .bind(&sha)
        .bind(&tpl.info.tags)
        .bind(actor)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "builtin signature sync failed", request_id, instance))?;
        builtin_count = builtin_count.saturating_add(1);
    }

    let mut repo_count = 0_usize;
    let mut skipped_count = 0_usize;
    for yaml in &repo_yamls {
        let Ok(tpl) = parse_fingerprinthub_v4_yaml(yaml) else {
            skipped_count = skipped_count.saturating_add(1);
            continue;
        };
        let sha = sha256_hex(yaml);
        sqlx::query(
            r#"
            INSERT INTO signature_rules (
                template_id, name, source, format, yaml_content, content_sha256,
                tags, is_enabled, created_by, synced_at
            )
            VALUES ($1, $2, 'fingerprinthub_repo', 'fingerprinthub_v4_yaml', $3, $4, $5, TRUE, $6, $7)
            ON CONFLICT (template_id) DO UPDATE
            SET name = EXCLUDED.name,
                source = EXCLUDED.source,
                yaml_content = EXCLUDED.yaml_content,
                content_sha256 = EXCLUDED.content_sha256,
                tags = EXCLUDED.tags,
                is_enabled = TRUE,
                synced_at = EXCLUDED.synced_at,
                updated_at = NOW()
            WHERE signature_rules.source <> 'custom'
            "#,
        )
        .bind(&tpl.id)
        .bind(&tpl.info.name)
        .bind(yaml)
        .bind(&sha)
        .bind(&tpl.info.tags)
        .bind(actor)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "repo signature sync failed", request_id, instance))?;
        repo_count = repo_count.saturating_add(1);
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: if actor.is_some() { "user" } else { "system" },
            actor_id: actor,
            action: "signatures.synced",
            resource_type: "signature_rule",
            resource_id: None,
            before_state: None,
            after_state: Some(serde_json::json!({
                "builtin_count": builtin_count,
                "repo_count": repo_count,
                "skipped_count": skipped_count,
                "source": source,
            })),
            source_ip,
            request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", request_id, instance))?;

    let synced_count = builtin_count.saturating_add(repo_count);
    Ok(SyncSignaturesResponse {
        synced_count,
        builtin_count,
        repo_count,
        skipped_count,
        source,
        repo_error,
        synced_at: now,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/signatures/sync",
    tag = "Signatures",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Synchronized built-in + FingerprintHub repo (GitHub/local dir) signatures and notified workers", body = SyncSignaturesResponse),
        (status = 403, description = "Admin permission SyncFingerprintHub required", body = ProblemDetails)
    )
)]
pub async fn sync_signatures(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SyncSignaturesResponse>, AppError> {
    let instance = "/api/v1/signatures/sync";
    auth.require(Permission::SyncFingerprintHub, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let resp = run_signature_sync(
        pool,
        &state.sig_sync,
        Some(auth.user.id),
        source_ip,
        auth.request_id,
    )
    .await?;

    broadcast_signature_reload(&state);
    Ok(Json(resp))
}

#[utoipa::path(
    post,
    path = "/api/v1/import/signatures",
    tag = "ImportExport",
    security(("bearer_auth" = [])),
    request_body = ImportSignaturesJsonRequest,
    responses(
        (status = 200, description = "Validated and imported FingerprintHub v4 YAML templates via JSON envelope", body = ImportSignaturesJsonResponse),
        (status = 422, description = "Validation error in schema or YAML templates", body = ProblemDetails)
    )
)]
pub async fn import_signatures_json(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ImportSignaturesJsonRequest>,
) -> Result<Json<ImportSignaturesJsonResponse>, AppError> {
    let instance = "/api/v1/import/signatures";
    auth.require(Permission::ImportData, instance)?;
    auth.require(Permission::ManageCustomSignatures, instance)?;
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
            message: "At least one YAML signature string is required.".to_string(),
        });
    }

    let mut parsed = Vec::with_capacity(payload.items.len());
    for (idx, yaml) in payload.items.iter().enumerate() {
        match parse_fingerprinthub_v4_yaml(yaml) {
            Ok(tpl) => parsed.push((tpl, sha256_hex(yaml), yaml.clone())),
            Err(msg) => violations.push(FieldViolation {
                field: format!("items[{idx}]"),
                code: "INVALID_FINGERPRINTHUB_YAML".to_string(),
                message: msg,
            }),
        }
    }

    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "JSON signature import failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let received_count = parsed.len();
    if payload.dry_run {
        return Ok(Json(ImportSignaturesJsonResponse {
            schema_version: EXPORT_SCHEMA_VERSION.to_string(),
            dry_run: true,
            received_count,
            upserted_count: received_count,
        }));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, instance))?;

    for (tpl, sha, yaml) in &parsed {
        sqlx::query(
            r#"
            INSERT INTO signature_rules (
                template_id, name, source, format, yaml_content, content_sha256,
                tags, is_enabled, created_by
            )
            VALUES ($1, $2, 'custom', 'fingerprinthub_v4_yaml', $3, $4, $5, TRUE, $6)
            ON CONFLICT (template_id) DO UPDATE
            SET name = EXCLUDED.name,
                yaml_content = EXCLUDED.yaml_content,
                content_sha256 = EXCLUDED.content_sha256,
                tags = EXCLUDED.tags,
                updated_at = NOW()
            "#,
        )
        .bind(&tpl.id)
        .bind(&tpl.info.name)
        .bind(yaml)
        .bind(sha)
        .bind(&tpl.info.tags)
        .bind(auth.user.id)
        .execute(&mut *tx)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "signature import upsert failed",
                auth.request_id,
                instance,
            )
        })?;
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "signatures.imported_json",
            resource_type: "signature_rule",
            resource_id: None,
            before_state: None,
            after_state: Some(serde_json::json!({ "upserted_count": received_count })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, instance))?;

    broadcast_signature_reload(&state);
    Ok(Json(ImportSignaturesJsonResponse {
        schema_version: EXPORT_SCHEMA_VERSION.to_string(),
        dry_run: false,
        received_count,
        upserted_count: received_count,
    }))
}
