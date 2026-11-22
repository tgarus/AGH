use asi_common::assets::AuditLogDto;
use asi_common::auth::{CreateUserRequest, UpdateUserRequest, UserSummary};
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::{Permission, Role};
use asi_common::validation::{validate_email, validate_password_strength, validate_username};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use sqlx::FromRow;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::routes::common::{extract_source_ip, map_db_err, require_db};
use crate::security::auth_extractor::AuthenticatedUser;
use crate::security::password::hash_password;

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    email: String,
    role: String,
    is_active: bool,
    preferred_locale: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
}

impl UserRow {
    fn into_summary(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<UserSummary, AppError> {
        let role = Role::from_db_str(&self.role).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid stored role '{}'", self.role)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(UserSummary {
            id: self.id,
            username: self.username,
            email: self.email,
            role,
            is_active: self.is_active,
            preferred_locale: self.preferred_locale,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        })
    }
}

#[derive(FromRow)]
struct AuditLogRow {
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

impl From<AuditLogRow> for AuditLogDto {
    fn from(row: AuditLogRow) -> Self {
        Self {
            id: row.id,
            actor_type: row.actor_type,
            actor_id: row.actor_id,
            action: row.action,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            before_state: row.before_state,
            after_state: row.after_state,
            source_ip: row.source_ip.map(|ip| ip.ip().to_string()),
            request_id: row.request_id,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct AuditLogFilter {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub resource_type: Option<String>,
    pub actor_id: Option<Uuid>,
}

fn validate_locale(locale: &str) -> Result<String, FieldViolation> {
    let norm = locale.trim().to_ascii_lowercase();
    if matches!(norm.as_str(), "pl" | "en") {
        Ok(norm)
    } else {
        Err(FieldViolation {
            field: "preferred_locale".to_string(),
            code: "INVALID_LOCALE".to_string(),
            message: "Supported locales are 'pl' and 'en'.".to_string(),
        })
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "Users",
    security(("bearer_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated user list", body = PaginatedResponse<UserSummary>),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn list_users(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<UserSummary>>, AppError> {
    let instance = "/api/v1/users";
    auth.require(Permission::ManageUsersAndAudit, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let pg = query.sanitized();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "user count failed", auth.request_id, instance))?;

    let rows: Vec<UserRow> = sqlx::query_as(
        r#"
        SELECT id, username, email, role, is_active, preferred_locale, created_at, updated_at, last_login_at
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "user query failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_summary(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    let total_u64 = u64::try_from(total.max(0)).unwrap_or(0);
    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(pg.page, pg.per_page, total_u64),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "Users",
    security(("bearer_auth" = [])),
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserSummary),
        (status = 409, description = "Username or email already exists", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn create_user(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserSummary>), AppError> {
    let instance = "/api/v1/users";
    auth.require(Permission::ManageUsersAndAudit, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut violations = Vec::new();
    let username = match validate_username(&payload.username) {
        Ok(v) => v,
        Err(msg) => {
            violations.push(FieldViolation {
                field: "username".to_string(),
                code: "INVALID_USERNAME".to_string(),
                message: msg,
            });
            String::new()
        }
    };
    let email = match validate_email(&payload.email) {
        Ok(v) => v,
        Err(msg) => {
            violations.push(FieldViolation {
                field: "email".to_string(),
                code: "INVALID_EMAIL".to_string(),
                message: msg,
            });
            String::new()
        }
    };
    if let Err(msg) = validate_password_strength(&payload.password) {
        violations.push(FieldViolation {
            field: "password".to_string(),
            code: "WEAK_PASSWORD".to_string(),
            message: msg,
        });
    }
    let locale = match payload.preferred_locale.as_deref() {
        Some(loc) => match validate_locale(loc) {
            Ok(v) => v,
            Err(violation) => {
                violations.push(violation);
                "pl".to_string()
            }
        },
        None => "pl".to_string(),
    };

    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "User payload failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let pw_hash = hash_password(&payload.password)
        .map_err(|err| AppError::new(err, auth.request_id, Some(instance.to_string())))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, instance))?;

    let row: UserRow = sqlx::query_as(
        r#"
        INSERT INTO users (username, email, password_hash, role, is_active, preferred_locale)
        VALUES ($1, $2, $3, $4, TRUE, $5)
        RETURNING id, username, email, role, is_active, preferred_locale, created_at, updated_at, last_login_at
        "#,
    )
    .bind(&username)
    .bind(&email)
    .bind(&pw_hash)
    .bind(payload.role.as_db_str())
    .bind(&locale)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "Username or email already exists.", auth.request_id, instance))?;

    let summary = row.into_summary(auth.request_id, instance)?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "user.created",
            resource_type: "user",
            resource_id: Some(summary.id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "username": summary.username,
                "email": summary.email,
                "role": summary.role,
                "preferred_locale": summary.preferred_locale,
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

    Ok((StatusCode::CREATED, Json(summary)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/users/{id}",
    tag = "Users",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "User UUID")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = UserSummary),
        (status = 404, description = "User not found", body = ProblemDetails),
        (status = 409, description = "Conflict (duplicate email or last active Admin)", body = ProblemDetails)
    )
)]
pub async fn update_user(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserSummary>, AppError> {
    let instance = format!("/api/v1/users/{id}");
    auth.require(Permission::ManageUsersAndAudit, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let existing: Option<UserRow> = sqlx::query_as(
        r#"
        SELECT id, username, email, role, is_active, preferred_locale, created_at, updated_at, last_login_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    let Some(existing) = existing else {
        return Err(AppError::new(
            DomainError::NotFound(format!("User {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let existing_summary = existing.into_summary(auth.request_id, &instance)?;

    let mut violations = Vec::new();
    let next_email = match payload.email.as_deref() {
        Some(raw) => match validate_email(raw) {
            Ok(v) => v,
            Err(msg) => {
                violations.push(FieldViolation {
                    field: "email".to_string(),
                    code: "INVALID_EMAIL".to_string(),
                    message: msg,
                });
                existing_summary.email.clone()
            }
        },
        None => existing_summary.email.clone(),
    };

    let next_locale = match payload.preferred_locale.as_deref() {
        Some(raw) => match validate_locale(raw) {
            Ok(v) => v,
            Err(violation) => {
                violations.push(violation);
                existing_summary.preferred_locale.clone()
            }
        },
        None => existing_summary.preferred_locale.clone(),
    };

    let next_password_hash =
        match payload.password.as_deref() {
            Some(pw) => {
                if let Err(msg) = validate_password_strength(pw) {
                    violations.push(FieldViolation {
                        field: "password".to_string(),
                        code: "WEAK_PASSWORD".to_string(),
                        message: msg,
                    });
                    None
                } else {
                    Some(hash_password(pw).map_err(|err| {
                        AppError::new(err, auth.request_id, Some(instance.clone()))
                    })?)
                }
            }
            None => None,
        };

    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "User update payload failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance),
        ));
    }

    let next_role = payload.role.unwrap_or(existing_summary.role);
    let next_active = payload.is_active.unwrap_or(existing_summary.is_active);

    if existing_summary.role == Role::Admin
        && existing_summary.is_active
        && (next_role != Role::Admin || !next_active)
    {
        let other_active_admins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE role = 'Admin' AND is_active = TRUE AND id <> $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "admin check failed", auth.request_id, &instance))?;

        if other_active_admins == 0 {
            return Err(AppError::new(
                DomainError::Conflict(
                    "Cannot demote or deactivate the last active Admin account.".to_string(),
                ),
                auth.request_id,
                Some(instance),
            ));
        }
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction failed", auth.request_id, &instance))?;

    let updated: UserRow = if let Some(pw_hash) = next_password_hash {
        sqlx::query_as(
            r#"
            UPDATE users
            SET email = $1, role = $2, is_active = $3, preferred_locale = $4, password_hash = $5, updated_at = NOW()
            WHERE id = $6
            RETURNING id, username, email, role, is_active, preferred_locale, created_at, updated_at, last_login_at
            "#,
        )
        .bind(&next_email)
        .bind(next_role.as_db_str())
        .bind(next_active)
        .bind(&next_locale)
        .bind(&pw_hash)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
    } else {
        sqlx::query_as(
            r#"
            UPDATE users
            SET email = $1, role = $2, is_active = $3, preferred_locale = $4, updated_at = NOW()
            WHERE id = $5
            RETURNING id, username, email, role, is_active, preferred_locale, created_at, updated_at, last_login_at
            "#,
        )
        .bind(&next_email)
        .bind(next_role.as_db_str())
        .bind(next_active)
        .bind(&next_locale)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
    }
    .map_err(|err| map_db_err(err, "Email address already in use.", auth.request_id, &instance))?;

    let next_summary = updated.into_summary(auth.request_id, &instance)?;
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "user.updated",
            resource_type: "user",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({
                "email": existing_summary.email,
                "role": existing_summary.role,
                "is_active": existing_summary.is_active,
                "preferred_locale": existing_summary.preferred_locale,
            })),
            after_state: Some(serde_json::json!({
                "email": next_summary.email,
                "role": next_summary.role,
                "is_active": next_summary.is_active,
                "preferred_locale": next_summary.preferred_locale,
                "password_changed": payload.password.is_some(),
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

    Ok(Json(next_summary))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/{id}",
    tag = "Users",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "User UUID")),
    responses(
        (status = 204, description = "User deleted"),
        (status = 404, description = "User not found", body = ProblemDetails),
        (status = 409, description = "Cannot delete self or last active Admin", body = ProblemDetails)
    )
)]
pub async fn delete_user(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/users/{id}");
    auth.require(Permission::ManageUsersAndAudit, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    if auth.user.id == id {
        return Err(AppError::new(
            DomainError::Conflict("Users cannot delete their own active account.".to_string()),
            auth.request_id,
            Some(instance),
        ));
    }

    let existing: Option<UserRow> = sqlx::query_as(
        r#"
        SELECT id, username, email, role, is_active, preferred_locale, created_at, updated_at, last_login_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    let Some(existing) = existing else {
        return Err(AppError::new(
            DomainError::NotFound(format!("User {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    if existing.role == "Admin" && existing.is_active {
        let other_admins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE role = 'Admin' AND is_active = TRUE AND id <> $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "admin check failed", auth.request_id, &instance))?;

        if other_admins == 0 {
            return Err(AppError::new(
                DomainError::Conflict("Cannot delete the last active Admin account.".to_string()),
                auth.request_id,
                Some(instance),
            ));
        }
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction failed", auth.request_id, &instance))?;

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "delete failed", auth.request_id, &instance))?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "user.deleted",
            resource_type: "user",
            resource_id: Some(id),
            before_state: Some(serde_json::json!({
                "username": existing.username,
                "role": existing.role,
            })),
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

#[utoipa::path(
    get,
    path = "/api/v1/users/directory",
    tag = "Users",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Active users directory for asset group & worker scoping", body = Vec<UserSummary>),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn list_users_directory(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<UserSummary>>, AppError> {
    let instance = "/api/v1/users/directory";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let rows: Vec<UserRow> = sqlx::query_as(
        r#"
        SELECT id, username, email, role, is_active, preferred_locale, created_at, updated_at, last_login_at
        FROM users
        WHERE is_active = TRUE
        ORDER BY username ASC
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "user directory query failed", auth.request_id, instance))?;

    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        users.push(row.into_summary(auth.request_id, instance)?);
    }
    Ok(Json(users))
}

#[utoipa::path(
    get,
    path = "/api/v1/audit-logs",
    tag = "Users",
    security(("bearer_auth" = [])),
    params(AuditLogFilter),
    responses(
        (status = 200, description = "Paginated audit logs", body = PaginatedResponse<AuditLogDto>),
        (status = 403, description = "Forbidden", body = ProblemDetails)
    )
)]
pub async fn list_audit_logs(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<AuditLogFilter>,
) -> Result<Json<PaginatedResponse<AuditLogDto>>, AppError> {
    let instance = "/api/v1/audit-logs";
    auth.require(Permission::ManageUsersAndAudit, instance)?;
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
        FROM audit_logs
        WHERE ($1::text IS NULL OR resource_type = $1)
          AND ($2::uuid IS NULL OR actor_id = $2)
        "#,
    )
    .bind(filter.resource_type.as_deref())
    .bind(filter.actor_id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "audit count failed", auth.request_id, instance))?;

    let rows: Vec<AuditLogRow> = sqlx::query_as(
        r#"
        SELECT id, actor_type, actor_id, action, resource_type, resource_id, before_state, after_state, source_ip, request_id, created_at
        FROM audit_logs
        WHERE ($1::text IS NULL OR resource_type = $1)
          AND ($2::uuid IS NULL OR actor_id = $2)
        ORDER BY created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(filter.resource_type.as_deref())
    .bind(filter.actor_id)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "audit query failed", auth.request_id, instance))?;

    let items = rows.into_iter().map(AuditLogDto::from).collect();
    let total_u64 = u64::try_from(total.max(0)).unwrap_or(0);
    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(pg.page, pg.per_page, total_u64),
    }))
}
