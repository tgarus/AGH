use asi_common::assets::{
    AddTargetsRequest, AssetGroupDetailDto, AssetGroupDto, AssetGroupMemberDto,
    AssetGroupTargetDto, CreateAssetGroupRequest, SetAssetGroupMembersRequest, TargetType,
    UpdateAssetGroupRequest,
};
use asi_common::error::{DomainError, FieldViolation, ProblemDetails};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use asi_common::rbac::Role;
use asi_common::validation::validate_target_value;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use crate::app::AppState;
use crate::audit::{insert_audit_log, AuditRecord};
use crate::error::AppError;
use crate::routes::common::{extract_source_ip, map_db_err, require_db};
use crate::routes::policies::ScanPolicyRow;
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(FromRow)]
struct AssetGroupRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    policy_id: Uuid,
    schedule_cron: Option<String>,
    sampling_enabled: bool,
    external_refs: serde_json::Value,
    target_count: i64,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<AssetGroupRow> for AssetGroupDto {
    fn from(row: AssetGroupRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            policy_id: row.policy_id,
            schedule_cron: row.schedule_cron,
            sampling_enabled: row.sampling_enabled,
            external_refs: row.external_refs,
            target_count: row.target_count,
            assigned_user_ids: Vec::new(),
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(FromRow)]
struct AssetGroupTargetRow {
    id: Uuid,
    asset_group_id: Uuid,
    target_type: String,
    value: String,
    notes: Option<String>,
    created_at: DateTime<Utc>,
}

impl AssetGroupTargetRow {
    fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<AssetGroupTargetDto, AppError> {
        let target_type = TargetType::from_db_str(&self.target_type).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid target_type '{}'", self.target_type)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(AssetGroupTargetDto {
            id: self.id,
            asset_group_id: self.asset_group_id,
            target_type,
            value: self.value,
            notes: self.notes,
            created_at: self.created_at,
        })
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/asset-groups",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Paginated asset groups", body = PaginatedResponse<AssetGroupDto>)
    )
)]
pub async fn list_asset_groups(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<AssetGroupDto>>, AppError> {
    let instance = "/api/v1/asset-groups";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let pg = query.sanitized();

    let is_admin = auth.user.role == Role::Admin;
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM asset_groups ag
        WHERE $1::bool
           OR NOT EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = ag.id)
           OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = ag.id AND m.user_id = $2)
        "#,
    )
    .bind(is_admin)
    .bind(auth.user.id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "count failed", auth.request_id, instance))?;

    let rows: Vec<AssetGroupRow> = sqlx::query_as(
        r#"
        SELECT ag.id, ag.name, ag.description, ag.policy_id, ag.schedule_cron, ag.sampling_enabled,
               ag.external_refs, COUNT(agt.id) AS target_count, ag.created_by, ag.created_at, ag.updated_at
        FROM asset_groups ag
        LEFT JOIN asset_group_targets agt ON agt.asset_group_id = ag.id
        WHERE $1::bool
           OR NOT EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = ag.id)
           OR EXISTS (SELECT 1 FROM asset_group_members m WHERE m.asset_group_id = ag.id AND m.user_id = $2)
        GROUP BY ag.id
        ORDER BY ag.created_at DESC
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(is_admin)
    .bind(auth.user.id)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "query failed", auth.request_id, instance))?;

    let member_map = fetch_all_group_member_ids(pool, auth.request_id, instance).await?;
    let items: Vec<AssetGroupDto> = rows
        .into_iter()
        .map(|row| {
            let mut dto = AssetGroupDto::from(row);
            dto.assigned_user_ids = member_map.get(&dto.id).cloned().unwrap_or_default();
            dto
        })
        .collect();
    let total_u64 = u64::try_from(total.max(0)).unwrap_or(0);
    Ok(Json(PaginatedResponse {
        items,
        pagination: PaginationMeta::new(pg.page, pg.per_page, total_u64),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/asset-groups",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    request_body = CreateAssetGroupRequest,
    responses(
        (status = 201, description = "Asset group created", body = AssetGroupDto),
        (status = 409, description = "Group name already exists or policy missing", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn create_asset_group(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAssetGroupRequest>,
) -> Result<(StatusCode, Json<AssetGroupDto>), AppError> {
    let instance = "/api/v1/asset-groups";
    auth.require(Permission::ManageAssetGroups, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;
    let source_ip = extract_source_ip(&headers);

    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Asset group payload failed validation.".to_string(),
                violations: vec![FieldViolation {
                    field: "name".to_string(),
                    code: "REQUIRED".to_string(),
                    message: "Asset group name cannot be empty.".to_string(),
                }],
            },
            auth.request_id,
            Some(instance.to_string()),
        ));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, instance))?;

    let row: AssetGroupRow = sqlx::query_as(
        r#"
        INSERT INTO asset_groups (name, description, policy_id, schedule_cron, sampling_enabled, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, name, description, policy_id, schedule_cron, sampling_enabled, external_refs,
                  0::bigint AS target_count, created_by, created_at, updated_at
        "#,
    )
    .bind(&name)
    .bind(payload.description.map(|s| s.trim().to_string()))
    .bind(payload.policy_id)
    .bind(payload.schedule_cron.map(|s| s.trim().to_string()))
    .bind(payload.sampling_enabled.unwrap_or(true))
    .bind(auth.user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "Asset group with this name already exists.",
            auth.request_id,
            instance,
        )
    })?;

    let dto = AssetGroupDto::from(row);
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "asset_group.created",
            resource_type: "asset_group",
            resource_id: Some(dto.id),
            before_state: None,
            after_state: serde_json::to_value(&dto).ok(),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, instance))?;

    Ok((StatusCode::CREATED, Json(dto)))
}

#[utoipa::path(
    get,
    path = "/api/v1/asset-groups/{id}",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Asset group UUID")),
    responses(
        (status = 200, description = "Asset group details with policy and targets", body = AssetGroupDetailDto),
        (status = 404, description = "Asset group not found", body = ProblemDetails)
    )
)]
pub async fn get_asset_group(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetGroupDetailDto>, AppError> {
    let instance = format!("/api/v1/asset-groups/{id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let group_row: Option<AssetGroupRow> = sqlx::query_as(
        r#"
        SELECT ag.id, ag.name, ag.description, ag.policy_id, ag.schedule_cron, ag.sampling_enabled,
               ag.external_refs, COUNT(agt.id) AS target_count, ag.created_by, ag.created_at, ag.updated_at
        FROM asset_groups ag
        LEFT JOIN asset_group_targets agt ON agt.asset_group_id = ag.id
        WHERE ag.id = $1
        GROUP BY ag.id
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "query failed", auth.request_id, &instance))?;

    let Some(group_row) = group_row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let policy_row: ScanPolicyRow = sqlx::query_as(
        r#"
        SELECT id, name, port_spec, discovery_tool, rate_pps, per_ip_cooldown_ms, subnet_concurrency,
               kill_grace_seconds, inactivity_threshold, tarpit_port_threshold, enable_nuclei, time_windows,
               created_at, updated_at
        FROM scan_policies
        WHERE id = $1
        "#,
    )
    .bind(group_row.policy_id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "policy lookup failed", auth.request_id, &instance))?;

    let target_rows: Vec<AssetGroupTargetRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, target_type, value, notes, created_at
        FROM asset_group_targets
        WHERE asset_group_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "targets lookup failed", auth.request_id, &instance))?;

    let targets = target_rows
        .into_iter()
        .map(|row| row.into_dto(auth.request_id, &instance))
        .collect::<Result<Vec<_>, _>>()?;

    let members = fetch_group_members(pool, id, auth.request_id, &instance).await?;
    let mut group_dto = AssetGroupDto::from(group_row);
    group_dto.assigned_user_ids = members.iter().map(|m| m.user_id).collect();

    Ok(Json(AssetGroupDetailDto {
        group: group_dto,
        policy: policy_row.into_dto(auth.request_id, &instance)?,
        targets,
        members,
    }))
}

#[derive(FromRow)]
struct AssetGroupMemberRow {
    asset_group_id: Uuid,
    user_id: Uuid,
    username: String,
    email: String,
    role: String,
    assigned_at: DateTime<Utc>,
}

async fn fetch_group_members(
    pool: &sqlx::PgPool,
    asset_group_id: Uuid,
    request_id: Option<Uuid>,
    instance: &str,
) -> Result<Vec<AssetGroupMemberDto>, AppError> {
    let rows: Vec<AssetGroupMemberRow> = sqlx::query_as(
        r#"
        SELECT agm.asset_group_id, agm.user_id, u.username, u.email, u.role, agm.assigned_at
        FROM asset_group_members agm
        INNER JOIN users u ON u.id = agm.user_id
        WHERE agm.asset_group_id = $1
        ORDER BY u.username ASC
        "#,
    )
    .bind(asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "group members lookup failed", request_id, instance))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let _ = row.asset_group_id;
        let role = Role::from_db_str(&row.role).unwrap_or(Role::ReadOnly);
        out.push(AssetGroupMemberDto {
            user_id: row.user_id,
            username: row.username,
            email: row.email,
            role,
            assigned_at: row.assigned_at,
        });
    }
    Ok(out)
}

async fn fetch_all_group_member_ids(
    pool: &sqlx::PgPool,
    request_id: Option<Uuid>,
    instance: &str,
) -> Result<std::collections::HashMap<Uuid, Vec<Uuid>>, AppError> {
    let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT asset_group_id, user_id FROM asset_group_members ORDER BY assigned_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "group members map failed", request_id, instance))?;

    let mut map: std::collections::HashMap<Uuid, Vec<Uuid>> = std::collections::HashMap::new();
    for (gid, uid) in rows {
        map.entry(gid).or_default().push(uid);
    }
    Ok(map)
}

#[utoipa::path(
    get,
    path = "/api/v1/asset-groups/{id}/members",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Asset group UUID")),
    responses(
        (status = 200, description = "Assigned users for asset group", body = Vec<AssetGroupMemberDto>),
        (status = 404, description = "Asset group not found", body = ProblemDetails)
    )
)]
pub async fn list_asset_group_members(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AssetGroupMemberDto>>, AppError> {
    let instance = format!("/api/v1/asset-groups/{id}/members");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM asset_groups WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|err| map_db_err(err, "group check failed", auth.request_id, &instance))?;

    if !exists {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    }

    let members = fetch_group_members(pool, id, auth.request_id, &instance).await?;
    Ok(Json(members))
}

#[utoipa::path(
    put,
    path = "/api/v1/asset-groups/{id}/members",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Asset group UUID")),
    request_body = SetAssetGroupMembersRequest,
    responses(
        (status = 200, description = "Updated assigned users for asset group", body = Vec<AssetGroupMemberDto>),
        (status = 404, description = "Asset group not found", body = ProblemDetails)
    )
)]
pub async fn set_asset_group_members(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<SetAssetGroupMembersRequest>,
) -> Result<Json<Vec<AssetGroupMemberDto>>, AppError> {
    let instance = format!("/api/v1/asset-groups/{id}/members");
    auth.require(Permission::ManageAssetGroups, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM asset_groups WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|err| map_db_err(err, "group check failed", auth.request_id, &instance))?;

    if !exists {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    }

    let mut unique_ids = Vec::new();
    for uid in payload.user_ids {
        if !unique_ids.contains(&uid) {
            unique_ids.push(uid);
        }
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    sqlx::query("DELETE FROM asset_group_members WHERE asset_group_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "clear members failed", auth.request_id, &instance))?;

    for uid in &unique_ids {
        sqlx::query(
            r#"
            INSERT INTO asset_group_members (asset_group_id, user_id, assigned_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (asset_group_id, user_id) DO NOTHING
            "#,
        )
        .bind(id)
        .bind(uid)
        .bind(auth.user.id)
        .execute(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "insert member failed", auth.request_id, &instance))?;
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "asset_group.members_updated",
            resource_type: "asset_group",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({ "user_ids": unique_ids })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    let members = fetch_group_members(pool, id, auth.request_id, &instance).await?;
    Ok(Json(members))
}

#[utoipa::path(
    patch,
    path = "/api/v1/asset-groups/{id}",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Asset group UUID")),
    request_body = UpdateAssetGroupRequest,
    responses(
        (status = 200, description = "Asset group updated", body = AssetGroupDto),
        (status = 404, description = "Asset group not found", body = ProblemDetails)
    )
)]
pub async fn update_asset_group(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateAssetGroupRequest>,
) -> Result<Json<AssetGroupDto>, AppError> {
    let instance = format!("/api/v1/asset-groups/{id}");
    auth.require(Permission::ManageAssetGroups, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let existing: Option<AssetGroupRow> = sqlx::query_as(
        r#"
        SELECT ag.id, ag.name, ag.description, ag.policy_id, ag.schedule_cron, ag.sampling_enabled,
               ag.external_refs, COUNT(agt.id) AS target_count, ag.created_by, ag.created_at, ag.updated_at
        FROM asset_groups ag
        LEFT JOIN asset_group_targets agt ON agt.asset_group_id = ag.id
        WHERE ag.id = $1
        GROUP BY ag.id
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    let Some(existing) = existing else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let before_dto = AssetGroupDto::from(existing);
    let next_name = payload
        .name
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| before_dto.name.clone());
    if next_name.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Asset group update failed validation.".to_string(),
                violations: vec![FieldViolation {
                    field: "name".to_string(),
                    code: "REQUIRED".to_string(),
                    message: "Asset group name cannot be empty.".to_string(),
                }],
            },
            auth.request_id,
            Some(instance),
        ));
    }

    let next_desc = payload
        .description
        .or_else(|| before_dto.description.clone());
    let next_policy = payload.policy_id.unwrap_or(before_dto.policy_id);
    let next_cron = payload
        .schedule_cron
        .or_else(|| before_dto.schedule_cron.clone());
    let next_sampling = payload
        .sampling_enabled
        .unwrap_or(before_dto.sampling_enabled);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let updated: AssetGroupRow = sqlx::query_as(
        r#"
        UPDATE asset_groups
        SET name = $1, description = $2, policy_id = $3, schedule_cron = $4, sampling_enabled = $5, updated_at = NOW()
        WHERE id = $6
        RETURNING id, name, description, policy_id, schedule_cron, sampling_enabled, external_refs,
                  $7::bigint AS target_count, created_by, created_at, updated_at
        "#,
    )
    .bind(&next_name)
    .bind(next_desc)
    .bind(next_policy)
    .bind(next_cron)
    .bind(next_sampling)
    .bind(id)
    .bind(before_dto.target_count)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "Asset group name already exists or policy does not exist.",
            auth.request_id,
            &instance,
        )
    })?;

    let mut after_dto = AssetGroupDto::from(updated);
    if let Ok(members) = fetch_group_members(pool, id, auth.request_id, &instance).await {
        after_dto.assigned_user_ids = members.into_iter().map(|m| m.user_id).collect();
    }
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "asset_group.updated",
            resource_type: "asset_group",
            resource_id: Some(id),
            before_state: serde_json::to_value(&before_dto).ok(),
            after_state: serde_json::to_value(&after_dto).ok(),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    Ok(Json(after_dto))
}

#[utoipa::path(
    delete,
    path = "/api/v1/asset-groups/{id}",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Asset group UUID")),
    responses(
        (status = 204, description = "Asset group deleted"),
        (status = 404, description = "Asset group not found", body = ProblemDetails)
    )
)]
pub async fn delete_asset_group(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/asset-groups/{id}");
    auth.require(Permission::ManageAssetGroups, &instance)?;
    auth.require(Permission::DeleteLocalTargetsAndResults, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let deleted_name: Option<String> =
        sqlx::query_scalar("DELETE FROM asset_groups WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|err| map_db_err(err, "delete failed", auth.request_id, &instance))?;

    let Some(name) = deleted_name else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "asset_group.deleted",
            resource_type: "asset_group",
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
    get,
    path = "/api/v1/asset-groups/{id}/targets",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Asset group UUID"), PaginationQuery),
    responses(
        (status = 200, description = "Paginated targets for asset group", body = PaginatedResponse<AssetGroupTargetDto>)
    )
)]
pub async fn list_group_targets(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<PaginatedResponse<AssetGroupTargetDto>>, AppError> {
    let instance = format!("/api/v1/asset-groups/{id}/targets");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let pg = query.sanitized();

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM asset_group_targets WHERE asset_group_id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|err| map_db_err(err, "count failed", auth.request_id, &instance))?;

    let rows: Vec<AssetGroupTargetRow> = sqlx::query_as(
        r#"
        SELECT id, asset_group_id, target_type, value, notes, created_at
        FROM asset_group_targets
        WHERE asset_group_id = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "query failed", auth.request_id, &instance))?;

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
    path = "/api/v1/asset-groups/{id}/targets",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Asset group UUID")),
    request_body = AddTargetsRequest,
    responses(
        (status = 201, description = "Targets added to asset group", body = Vec<AssetGroupTargetDto>),
        (status = 404, description = "Asset group not found", body = ProblemDetails),
        (status = 422, description = "Validation error", body = ProblemDetails)
    )
)]
pub async fn add_group_targets(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<AddTargetsRequest>,
) -> Result<(StatusCode, Json<Vec<AssetGroupTargetDto>>), AppError> {
    let instance = format!("/api/v1/asset-groups/{id}/targets");
    auth.require(Permission::ManageAssetGroups, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    if payload.targets.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "Targets list cannot be empty.".to_string(),
                violations: vec![FieldViolation {
                    field: "targets".to_string(),
                    code: "REQUIRED".to_string(),
                    message: "At least one target is required.".to_string(),
                }],
            },
            auth.request_id,
            Some(instance),
        ));
    }

    let mut normalized = Vec::with_capacity(payload.targets.len());
    let mut violations = Vec::new();
    for (idx, item) in payload.targets.iter().enumerate() {
        match validate_target_value(
            &format!("targets[{idx}].value"),
            item.target_type,
            &item.value,
        ) {
            Ok(norm_val) => normalized.push((item.target_type, norm_val, item.notes.clone())),
            Err(violation) => violations.push(violation),
        }
    }

    if !violations.is_empty() {
        return Err(AppError::new(
            DomainError::Validation {
                detail: "One or more targets failed validation.".to_string(),
                violations,
            },
            auth.request_id,
            Some(instance),
        ));
    }

    let group_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM asset_groups WHERE id = $1)")
            .bind(id)
            .fetch_one(pool)
            .await
            .map_err(|err| map_db_err(err, "lookup failed", auth.request_id, &instance))?;

    if !group_exists {
        return Err(AppError::new(
            DomainError::NotFound(format!("Asset group {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let mut inserted = Vec::new();
    for (target_type, value, notes) in normalized {
        let row: Option<AssetGroupTargetRow> = sqlx::query_as(
            r#"
            INSERT INTO asset_group_targets (asset_group_id, target_type, value, notes)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (asset_group_id, target_type, value) DO NOTHING
            RETURNING id, asset_group_id, target_type, value, notes, created_at
            "#,
        )
        .bind(id)
        .bind(target_type.as_db_str())
        .bind(&value)
        .bind(notes)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| map_db_err(err, "target insert failed", auth.request_id, &instance))?;

        if let Some(row) = row {
            inserted.push(row.into_dto(auth.request_id, &instance)?);
        }
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "asset_group_targets.added",
            resource_type: "asset_group",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({ "inserted_count": inserted.len() })),
            source_ip,
            request_id: auth.request_id,
        },
    )
    .await
    .map_err(|err| map_db_err(err, "audit log failed", auth.request_id, &instance))?;

    tx.commit()
        .await
        .map_err(|err| map_db_err(err, "commit failed", auth.request_id, &instance))?;

    Ok((StatusCode::CREATED, Json(inserted)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/asset-groups/{id}/targets/{target_id}",
    tag = "AssetGroups",
    security(("bearer_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Asset group UUID"),
        ("target_id" = Uuid, Path, description = "Target UUID")
    ),
    responses(
        (status = 204, description = "Target deleted"),
        (status = 404, description = "Target not found", body = ProblemDetails)
    )
)]
pub async fn delete_group_target(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, target_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let instance = format!("/api/v1/asset-groups/{id}/targets/{target_id}");
    auth.require(Permission::ManageAssetGroups, &instance)?;
    auth.require(Permission::DeleteLocalTargetsAndResults, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "transaction error", auth.request_id, &instance))?;

    let deleted: Option<String> = sqlx::query_scalar(
        "DELETE FROM asset_group_targets WHERE id = $1 AND asset_group_id = $2 RETURNING value",
    )
    .bind(target_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| map_db_err(err, "delete failed", auth.request_id, &instance))?;

    let Some(value) = deleted else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Target {target_id} not found in group {id}.")),
            auth.request_id,
            Some(instance),
        ));
    };

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "asset_group_target.deleted",
            resource_type: "asset_group_target",
            resource_id: Some(target_id),
            before_state: Some(serde_json::json!({ "asset_group_id": id, "value": value })),
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
