use asi_common::diff::{BulletItem, DiffEventKind, DiffSeverity};
use asi_common::error::{DomainError, ProblemDetails};
use asi_common::inventory::DiffEventDto;
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::{Permission, Role};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
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

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct DiffFilterQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub asset_group_id: Option<Uuid>,
    pub host_id: Option<Uuid>,
    pub event_kind: Option<DiffEventKind>,
    pub severity: Option<DiffSeverity>,
    pub acknowledged: Option<bool>,
}

#[derive(FromRow)]
pub(crate) struct DiffEventRow {
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

impl DiffEventRow {
    pub(crate) fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<DiffEventDto, AppError> {
        let event_kind = DiffEventKind::from_db_str(&self.event_kind).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid diff event_kind '{}'", self.event_kind)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        let severity = DiffSeverity::from_db_str(&self.severity).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid diff severity '{}'", self.severity)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        let bullet_items: Vec<BulletItem> =
            serde_json::from_value(self.bullet_items).unwrap_or_default();

        Ok(DiffEventDto {
            id: self.id,
            host_id: self.host_id,
            asset_group_id: self.asset_group_id,
            ip_addr: self.ip_addr.ip(),
            scan_run_id: self.scan_run_id,
            event_kind,
            severity,
            bullet_items,
            previous_snapshot: self.previous_snapshot,
            current_snapshot: self.current_snapshot,
            acknowledged_by: self.acknowledged_by,
            acknowledged_at: self.acknowledged_at,
            detected_at: self.detected_at,
        })
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/diffs",
    tag = "Diffs",
    security(("bearer_auth" = [])),
    params(DiffFilterQuery),
    responses(
        (status = 200, description = "Paginated Diff Engine events with structured bullet_items", body = PaginatedResponse<DiffEventDto>)
    )
)]
pub async fn list_diffs(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<DiffFilterQuery>,
) -> Result<Json<PaginatedResponse<DiffEventDto>>, AppError> {
    let instance = "/api/v1/diffs";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let pg = PaginationQuery {
        page: filter.page,
        per_page: filter.per_page,
        ..Default::default()
    }
    .sanitized();

    let kind_filter = filter.event_kind.map(|k| k.as_db_str().to_string());
    let sev_filter = filter.severity.map(|s| s.as_db_str().to_string());
    let is_admin = auth.user.role == Role::Admin;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM diff_events de
        INNER JOIN hosts h ON h.id = de.host_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
          AND ($2::uuid IS NULL OR de.host_id = $2)
          AND ($3::text IS NULL OR de.event_kind = $3)
          AND ($4::text IS NULL OR de.severity = $4)
          AND (
              $5::bool IS NULL
              OR ($5 = TRUE AND de.acknowledged_at IS NOT NULL)
              OR ($5 = FALSE AND de.acknowledged_at IS NULL)
          )
          AND (
              $6::bool
              OR NOT EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = h.asset_group_id)
              OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = h.asset_group_id AND m.user_id = $7)
          )
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(filter.host_id)
    .bind(&kind_filter)
    .bind(&sev_filter)
    .bind(filter.acknowledged)
    .bind(is_admin)
    .bind(auth.user.id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "diffs count failed", auth.request_id, instance))?;

    let rows: Vec<DiffEventRow> = sqlx::query_as(
        r#"
        SELECT de.id, de.host_id, h.asset_group_id, h.ip_addr, de.scan_run_id,
               de.event_kind, de.severity, de.bullet_items,
               de.previous_snapshot, de.current_snapshot,
               de.acknowledged_by, de.acknowledged_at, de.detected_at
        FROM diff_events de
        INNER JOIN hosts h ON h.id = de.host_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
          AND ($2::uuid IS NULL OR de.host_id = $2)
          AND ($3::text IS NULL OR de.event_kind = $3)
          AND ($4::text IS NULL OR de.severity = $4)
          AND (
              $5::bool IS NULL
              OR ($5 = TRUE AND de.acknowledged_at IS NOT NULL)
              OR ($5 = FALSE AND de.acknowledged_at IS NULL)
          )
          AND (
              $6::bool
              OR NOT EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = h.asset_group_id)
              OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = h.asset_group_id AND m.user_id = $7)
          )
        ORDER BY de.detected_at DESC
        LIMIT $8 OFFSET $9
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(filter.host_id)
    .bind(&kind_filter)
    .bind(&sev_filter)
    .bind(filter.acknowledged)
    .bind(is_admin)
    .bind(auth.user.id)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "diffs query failed", auth.request_id, instance))?;

    let items = rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, instance))
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
    path = "/api/v1/diffs/{id}",
    tag = "Diffs",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Diff event UUID")),
    responses(
        (status = 200, description = "Diff event detail", body = DiffEventDto),
        (status = 404, description = "Diff event not found", body = ProblemDetails)
    )
)]
pub async fn get_diff(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<DiffEventDto>, AppError> {
    let instance = format!("/api/v1/diffs/{id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let row: Option<DiffEventRow> = sqlx::query_as(
        r#"
        SELECT de.id, de.host_id, h.asset_group_id, h.ip_addr, de.scan_run_id,
               de.event_kind, de.severity, de.bullet_items,
               de.previous_snapshot, de.current_snapshot,
               de.acknowledged_by, de.acknowledged_at, de.detected_at
        FROM diff_events de
        INNER JOIN hosts h ON h.id = de.host_id
        WHERE de.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "diff lookup failed", auth.request_id, &instance))?;

    let Some(row) = row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Diff event {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    Ok(Json(row.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/diffs/{id}/acknowledge",
    tag = "Diffs",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Diff event UUID")),
    responses(
        (status = 200, description = "Diff event acknowledged by analyst", body = DiffEventDto),
        (status = 403, description = "Permission AcknowledgeDiffs required", body = ProblemDetails),
        (status = 404, description = "Diff event not found", body = ProblemDetails)
    )
)]
pub async fn acknowledge_diff(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<DiffEventDto>, AppError> {
    let instance = format!("/api/v1/diffs/{id}/acknowledge");
    auth.require(Permission::AcknowledgeDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, &instance))?;

    let updated: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE diff_events
        SET acknowledged_by = COALESCE(acknowledged_by, $1),
            acknowledged_at = COALESCE(acknowledged_at, NOW())
        WHERE id = $2
        RETURNING id
        "#,
    )
    .bind(auth.user.id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "diff acknowledge failed", auth.request_id, &instance))?;

    if updated.is_none() {
        return Err(AppError::new(
            DomainError::NotFound(format!("Diff event {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "diff_event.acknowledged",
            resource_type: "diff_event",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({ "acknowledged_by": auth.user.id })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    let row: DiffEventRow = sqlx::query_as(
        r#"
        SELECT de.id, de.host_id, h.asset_group_id, h.ip_addr, de.scan_run_id,
               de.event_kind, de.severity, de.bullet_items,
               de.previous_snapshot, de.current_snapshot,
               de.acknowledged_by, de.acknowledged_at, de.detected_at
        FROM diff_events de
        INNER JOIN hosts h ON h.id = de.host_id
        WHERE de.id = $1
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "diff reload failed", auth.request_id, &instance))?;

    Ok(Json(row.into_dto(auth.request_id, &instance)?))
}
