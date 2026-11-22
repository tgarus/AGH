use std::net::IpAddr;

use asi_common::diff::{BulletItem, DiffEventKind, DiffOp, DiffSeverity};
use asi_common::error::{DomainError, ProblemDetails};
use asi_common::notification::{
    CreateNotificationChannelRequest, NotificationChannelDto, NotificationChannelType,
    NotificationDeliveryDto, NotificationMessage, TestNotificationResponse,
    UpdateNotificationChannelRequest,
};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::notifications::sinks::build_sink;
use crate::routes::common::{extract_source_ip, map_db_err, require_db};
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(FromRow)]
struct ChannelRow {
    id: Uuid,
    name: String,
    channel_type: String,
    asset_group_id: Option<Uuid>,
    notify_on_confirmed: bool,
    notify_on_variance: bool,
    config_public: serde_json::Value,
    has_secret: bool,
    is_enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ChannelRow {
    fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<NotificationChannelDto, AppError> {
        let channel_type =
            NotificationChannelType::from_db_str(&self.channel_type).ok_or_else(|| {
                AppError::new(
                    DomainError::Internal(format!("invalid channel_type '{}'", self.channel_type)),
                    request_id,
                    Some(instance.to_string()),
                )
            })?;
        Ok(NotificationChannelDto {
            id: self.id,
            name: self.name,
            channel_type,
            asset_group_id: self.asset_group_id,
            notify_on_confirmed: self.notify_on_confirmed,
            notify_on_variance: self.notify_on_variance,
            config_public: self.config_public,
            has_secret: self.has_secret,
            is_enabled: self.is_enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(FromRow)]
struct FullChannelSecretRow {
    id: Uuid,
    channel_type: String,
    config_public: serde_json::Value,
    secret_ciphertext: Option<Vec<u8>>,
    secret_nonce: Option<Vec<u8>>,
}

#[derive(FromRow)]
struct DeliveryRow {
    id: Uuid,
    channel_id: Uuid,
    channel_name: String,
    diff_event_id: Uuid,
    status: String,
    attempt_count: i32,
    next_retry_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    sent_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/api/v1/notifications/channels",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated notification channels (secrets redacted)", body = PaginatedResponse<NotificationChannelDto>)
    )
)]
pub async fn list_notification_channels(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<NotificationChannelDto>>, AppError> {
    let instance = "/api/v1/notifications/channels";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let pg = query.sanitized();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_channels")
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "channels count failed", auth.request_id, instance))?;

    let rows: Vec<ChannelRow> = sqlx::query_as(
        r#"
        SELECT id, name, channel_type, asset_group_id, notify_on_confirmed, notify_on_variance,
               config_public, (secret_ciphertext IS NOT NULL) AS has_secret,
               is_enabled, created_at, updated_at
        FROM notification_channels
        ORDER BY name ASC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "channels query failed", auth.request_id, instance))?;

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
    post,
    path = "/api/v1/notifications/channels",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    request_body = CreateNotificationChannelRequest,
    responses(
        (status = 201, description = "Notification channel created with AES-256-GCM encrypted secret", body = NotificationChannelDto),
        (status = 403, description = "Admin permission ManageGlobalPoliciesAndNotifications required", body = ProblemDetails),
        (status = 409, description = "Channel name already exists", body = ProblemDetails),
        (status = 422, description = "Invalid sink configuration", body = ProblemDetails)
    )
)]
pub async fn create_notification_channel(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateNotificationChannelRequest>,
) -> Result<(StatusCode, Json<NotificationChannelDto>), AppError> {
    let instance = "/api/v1/notifications/channels";
    auth.require(Permission::ManageGlobalPoliciesAndNotifications, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let trimmed_name = payload.name.trim().to_string();
    if trimmed_name.is_empty() {
        return Err(AppError::new(
            DomainError::BadRequest("Channel name cannot be empty.".to_string()),
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let secret_opt = payload
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    // Validate sink configuration before persisting
    build_sink(
        payload.channel_type,
        &payload.config_public,
        secret_opt.as_deref(),
    )
    .map_err(|domain| AppError::new(domain, auth.request_id, Some(instance.to_string())))?;

    let (ct_opt, nonce_opt) = match secret_opt {
        Some(ref sec) => {
            let (ct, nonce) = state.secret_box.encrypt(sec.as_bytes()).map_err(|domain| {
                AppError::new(domain, auth.request_id, Some(instance.to_string()))
            })?;
            (Some(ct), Some(nonce))
        }
        None => (None, None),
    };

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, instance))?;

    let row: ChannelRow = sqlx::query_as(
        r#"
        INSERT INTO notification_channels (
            name, channel_type, asset_group_id, notify_on_confirmed, notify_on_variance,
            config_public, secret_ciphertext, secret_nonce, is_enabled
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, name, channel_type, asset_group_id, notify_on_confirmed, notify_on_variance,
                  config_public, (secret_ciphertext IS NOT NULL) AS has_secret,
                  is_enabled, created_at, updated_at
        "#,
    )
    .bind(&trimmed_name)
    .bind(payload.channel_type.as_db_str())
    .bind(payload.asset_group_id)
    .bind(payload.notify_on_confirmed.unwrap_or(true))
    .bind(payload.notify_on_variance.unwrap_or(true))
    .bind(&payload.config_public)
    .bind(ct_opt)
    .bind(nonce_opt)
    .bind(payload.is_enabled.unwrap_or(true))
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "Notification channel with this name already exists.",
            auth.request_id,
            instance,
        )
    })?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "notification_channel.created",
            resource_type: "notification_channel",
            resource_id: Some(row.id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "name": row.name,
                "channel_type": row.channel_type,
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

    Ok((
        StatusCode::CREATED,
        Json(row.into_dto(auth.request_id, instance)?),
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/notifications/channels/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Notification channel UUID")),
    request_body = UpdateNotificationChannelRequest,
    responses(
        (status = 200, description = "Notification channel updated", body = NotificationChannelDto),
        (status = 404, description = "Notification channel not found", body = ProblemDetails)
    )
)]
pub async fn update_notification_channel(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateNotificationChannelRequest>,
) -> Result<Json<NotificationChannelDto>, AppError> {
    let instance = format!("/api/v1/notifications/channels/{id}");
    auth.require(Permission::ManageGlobalPoliciesAndNotifications, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, &instance))?;

    let current: Option<ChannelRow> = sqlx::query_as(
        r#"
        SELECT id, name, channel_type, asset_group_id, notify_on_confirmed, notify_on_variance,
               config_public, (secret_ciphertext IS NOT NULL) AS has_secret,
               is_enabled, created_at, updated_at
        FROM notification_channels
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "channel lookup failed", auth.request_id, &instance))?;

    let Some(current) = current else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Notification channel {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let channel_type =
        NotificationChannelType::from_db_str(&current.channel_type).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid channel_type '{}'", current.channel_type)),
                auth.request_id,
                Some(instance.clone()),
            )
        })?;

    let next_name = payload
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or(current.name);
    let next_confirmed = payload
        .notify_on_confirmed
        .unwrap_or(current.notify_on_confirmed);
    let next_variance = payload
        .notify_on_variance
        .unwrap_or(current.notify_on_variance);
    let next_config = payload.config_public.unwrap_or(current.config_public);
    let next_enabled = payload.is_enabled.unwrap_or(current.is_enabled);

    build_sink(channel_type, &next_config, None)
        .map_err(|domain| AppError::new(domain, auth.request_id, Some(instance.clone())))?;

    let rotated_secret = match payload
        .secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(sec) => {
            let (ct, nonce) = state
                .secret_box
                .encrypt(sec.as_bytes())
                .map_err(|domain| AppError::new(domain, auth.request_id, Some(instance.clone())))?;
            Some((ct, nonce))
        }
        None => None,
    };

    let updated: ChannelRow = match rotated_secret {
        Some((ct, nonce)) => {
            sqlx::query_as(
                r#"
                UPDATE notification_channels
                SET name = $1, notify_on_confirmed = $2, notify_on_variance = $3,
                    config_public = $4, secret_ciphertext = $5, secret_nonce = $6,
                    is_enabled = $7, updated_at = NOW()
                WHERE id = $8
                RETURNING id, name, channel_type, asset_group_id, notify_on_confirmed, notify_on_variance,
                          config_public, (secret_ciphertext IS NOT NULL) AS has_secret,
                          is_enabled, created_at, updated_at
                "#,
            )
            .bind(&next_name)
            .bind(next_confirmed)
            .bind(next_variance)
            .bind(&next_config)
            .bind(ct)
            .bind(nonce)
            .bind(next_enabled)
            .bind(id)
            .fetch_one(&mut *tx)
            .await
        }
        None => {
            sqlx::query_as(
                r#"
                UPDATE notification_channels
                SET name = $1, notify_on_confirmed = $2, notify_on_variance = $3,
                    config_public = $4, is_enabled = $5, updated_at = NOW()
                WHERE id = $6
                RETURNING id, name, channel_type, asset_group_id, notify_on_confirmed, notify_on_variance,
                          config_public, (secret_ciphertext IS NOT NULL) AS has_secret,
                          is_enabled, created_at, updated_at
                "#,
            )
            .bind(&next_name)
            .bind(next_confirmed)
            .bind(next_variance)
            .bind(&next_config)
            .bind(next_enabled)
            .bind(id)
            .fetch_one(&mut *tx)
            .await
        }
    }
    .map_err(|err| map_db_err(err, "channel update failed", auth.request_id, &instance))?;

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "notification_channel.updated",
            resource_type: "notification_channel",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "name": updated.name,
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

    Ok(Json(updated.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    delete,
    path = "/api/v1/notifications/channels/{id}",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Notification channel UUID")),
    responses(
        (status = 204, description = "Notification channel deleted"),
        (status = 404, description = "Notification channel not found", body = ProblemDetails)
    )
)]
pub async fn delete_notification_channel(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/notifications/channels/{id}");
    auth.require(Permission::ManageGlobalPoliciesAndNotifications, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, &instance))?;

    let deleted: Option<String> =
        sqlx::query_scalar("DELETE FROM notification_channels WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "channel delete failed", auth.request_id, &instance))?;

    let Some(name) = deleted else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Notification channel {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "notification_channel.deleted",
            resource_type: "notification_channel",
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

#[utoipa::path(
    post,
    path = "/api/v1/notifications/channels/{id}/test",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Notification channel UUID")),
    responses(
        (status = 200, description = "Synthetic test notification dispatch outcome", body = TestNotificationResponse),
        (status = 404, description = "Notification channel not found", body = ProblemDetails)
    )
)]
pub async fn test_notification_channel(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestNotificationResponse>, AppError> {
    let instance = format!("/api/v1/notifications/channels/{id}/test");
    auth.require(Permission::ManageGlobalPoliciesAndNotifications, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let row: Option<FullChannelSecretRow> = sqlx::query_as(
        r#"
        SELECT id, channel_type, config_public, secret_ciphertext, secret_nonce
        FROM notification_channels
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "channel lookup failed", auth.request_id, &instance))?;

    let Some(row) = row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Notification channel {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let channel_type =
        NotificationChannelType::from_db_str(&row.channel_type).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid channel_type '{}'", row.channel_type)),
                auth.request_id,
                Some(instance.clone()),
            )
        })?;

    let decrypted = match (&row.secret_ciphertext, &row.secret_nonce) {
        (Some(ct), Some(nonce)) => {
            let raw = state
                .secret_box
                .decrypt(ct, nonce)
                .map_err(|domain| AppError::new(domain, auth.request_id, Some(instance.clone())))?;
            Some(String::from_utf8(raw).map_err(|e| {
                AppError::new(
                    DomainError::Internal(format!("secret UTF-8 decode failed: {e}")),
                    auth.request_id,
                    Some(instance.clone()),
                )
            })?)
        }
        _ => None,
    };

    let sink = build_sink(channel_type, &row.config_public, decrypted.as_deref())
        .map_err(|domain| AppError::new(domain, auth.request_id, Some(instance.clone())))?;

    let synthetic = NotificationMessage {
        delivery_id: row.id,
        diff_event_id: Uuid::new_v4(),
        asset_group_name: "ASI Test Harness".to_string(),
        host_id: Uuid::new_v4(),
        ip_addr: "172.28.0.10".parse::<IpAddr>().map_err(|_| {
            AppError::new(
                DomainError::Internal("static IP parse failed".to_string()),
                auth.request_id,
                Some(instance.clone()),
            )
        })?,
        event_kind: DiffEventKind::ConfirmedChange,
        severity: DiffSeverity::Info,
        bullet_items: vec![BulletItem {
            op: DiffOp::Added,
            key: "service_added".to_string(),
            params: serde_json::json!({ "port": 443, "proto": "tcp", "service_name": "https" }),
        }],
        detected_at: Utc::now(),
    };

    match sink.send(&synthetic).await {
        Ok(()) => Ok(Json(TestNotificationResponse {
            delivered: true,
            detail: "Test notification delivered successfully.".to_string(),
        })),
        Err(err) => Ok(Json(TestNotificationResponse {
            delivered: false,
            detail: err.to_string(),
        })),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/notifications/deliveries",
    tag = "Notifications",
    security(("bearer_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated notification delivery audit & retry log", body = PaginatedResponse<NotificationDeliveryDto>)
    )
)]
pub async fn list_notification_deliveries(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<NotificationDeliveryDto>>, AppError> {
    let instance = "/api/v1/notifications/deliveries";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let pg = query.sanitized();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_deliveries")
        .fetch_one(pool)
        .await
        .map_err(|err| map_db_err(err, "deliveries count failed", auth.request_id, instance))?;

    let rows: Vec<DeliveryRow> = sqlx::query_as(
        r#"
        SELECT nd.id, nd.channel_id, nc.name AS channel_name, nd.diff_event_id,
               nd.status, nd.attempt_count, nd.next_retry_at, nd.last_error,
               nd.sent_at, nd.created_at
        FROM notification_deliveries nd
        INNER JOIN notification_channels nc ON nc.id = nd.channel_id
        ORDER BY nd.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "deliveries query failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|r| NotificationDeliveryDto {
            id: r.id,
            channel_id: r.channel_id,
            channel_name: r.channel_name,
            diff_event_id: r.diff_event_id,
            status: r.status,
            attempt_count: r.attempt_count,
            next_retry_at: r.next_retry_at,
            last_error: r.last_error,
            sent_at: r.sent_at,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(
            pg.page,
            pg.per_page,
            u64::try_from(total.max(0)).unwrap_or(0),
        ),
    }))
}
