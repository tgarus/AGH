use std::collections::HashMap;
use std::net::IpAddr;

use asi_common::diff::TimeSlot;
use asi_common::error::{DomainError, ProblemDetails};
use asi_common::inventory::{
    HostAvailabilitySampleDto, HostDetailDto, HostHostnameDto, HostPortDto, HostStatus,
    HostSummaryDto, PortState, TarpitOverrideRequest, TlsCertificateDto, UpdateHostMetadataRequest,
    WebObservationDto,
};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use asi_common::worker::WebCookieMeta;
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
pub struct HostFilterQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub asset_group_id: Option<Uuid>,
    pub status: Option<HostStatus>,
    pub is_unstable: Option<bool>,
    pub is_probable_tarpit: Option<bool>,
    pub q: Option<String>,
}

#[derive(FromRow)]
pub(crate) struct HostSummaryRow {
    id: Uuid,
    asset_group_id: Uuid,
    asset_group_name: String,
    ip_addr: IpNetwork,
    status: String,
    consecutive_misses: i32,
    is_unstable: bool,
    is_probable_tarpit: bool,
    availability_profile: serde_json::Value,
    auto_tags: Vec<String>,
    manual_tags: Vec<String>,
    notes: Option<String>,
    owner_hint: Option<String>,
    tarpit_override_force_sv: bool,
    open_port_count: i64,
    first_seen_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
    last_scanned_at: Option<DateTime<Utc>>,
}

impl HostSummaryRow {
    pub(crate) fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<HostSummaryDto, AppError> {
        let status = HostStatus::from_db_str(&self.status).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid host status '{}'", self.status)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        Ok(HostSummaryDto {
            id: self.id,
            asset_group_id: self.asset_group_id,
            asset_group_name: self.asset_group_name,
            ip_addr: self.ip_addr.ip(),
            status,
            consecutive_misses: self.consecutive_misses,
            is_unstable: self.is_unstable,
            is_probable_tarpit: self.is_probable_tarpit,
            availability_profile: self.availability_profile,
            auto_tags: self.auto_tags,
            manual_tags: self.manual_tags,
            notes: self.notes,
            owner_hint: self.owner_hint,
            tarpit_override_force_sv: self.tarpit_override_force_sv,
            open_port_count: self.open_port_count,
            first_seen_at: self.first_seen_at,
            last_seen_at: self.last_seen_at,
            last_scanned_at: self.last_scanned_at,
        })
    }
}

#[derive(FromRow)]
struct HostnameRow {
    id: Uuid,
    hostname: String,
    source: String,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct HostPortRow {
    id: Uuid,
    host_id: Uuid,
    port: i32,
    protocol: String,
    state: String,
    consecutive_misses: i32,
    service_name: Option<String>,
    product: Option<String>,
    version: Option<String>,
    extra_info: Option<String>,
    is_web_candidate: bool,
    tunnel: Option<String>,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct TlsCertRow {
    host_port_id: Uuid,
    sha256_fingerprint: String,
    subject_cn: Option<String>,
    issuer_cn: Option<String>,
    san_dns: Vec<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    is_self_signed: bool,
    observed_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct WebObsRow {
    id: Uuid,
    host_port_id: Uuid,
    vhost: String,
    scheme: String,
    http_status: Option<i32>,
    final_url: Option<String>,
    redirect_target: Option<String>,
    title: Option<String>,
    headers_filtered: serde_json::Value,
    cookies_meta: serde_json::Value,
    favicon_mmh3: Option<i64>,
    matched_technologies: serde_json::Value,
    detected_paths: Vec<String>,
    last_observed_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct SampleRow {
    id: Uuid,
    scan_run_id: Option<Uuid>,
    time_slot: String,
    is_alive: bool,
    open_ports_hash: String,
    sampled_at: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/api/v1/hosts",
    tag = "Hosts",
    security(("bearer_auth" = [])),
    params(HostFilterQuery),
    responses(
        (status = 200, description = "Paginated discovered hosts inventory", body = PaginatedResponse<HostSummaryDto>)
    )
)]
pub async fn list_hosts(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<HostFilterQuery>,
) -> Result<Json<PaginatedResponse<HostSummaryDto>>, AppError> {
    let instance = "/api/v1/hosts";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let pg = PaginationQuery {
        page: filter.page,
        per_page: filter.per_page,
        ..Default::default()
    }
    .sanitized();

    let status_filter = filter.status.map(|s| s.as_db_str().to_string());
    let search_pattern = filter
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("%{s}%"));

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM hosts h
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE ($1::uuid IS NULL OR h.asset_group_id = $1)
          AND ($2::text IS NULL OR h.status = $2)
          AND ($3::bool IS NULL OR h.is_unstable = $3)
          AND ($4::bool IS NULL OR h.is_probable_tarpit = $4)
          AND (
              $5::text IS NULL
              OR h.ip_addr::text ILIKE $5
              OR ag.name ILIKE $5
              OR EXISTS (
                  SELECT 1 FROM host_hostnames hh
                  WHERE hh.host_id = h.id AND hh.hostname ILIKE $5
              )
          )
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(&status_filter)
    .bind(filter.is_unstable)
    .bind(filter.is_probable_tarpit)
    .bind(&search_pattern)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "hosts count failed", auth.request_id, instance))?;

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
          AND ($2::text IS NULL OR h.status = $2)
          AND ($3::bool IS NULL OR h.is_unstable = $3)
          AND ($4::bool IS NULL OR h.is_probable_tarpit = $4)
          AND (
              $5::text IS NULL
              OR h.ip_addr::text ILIKE $5
              OR ag.name ILIKE $5
              OR EXISTS (
                  SELECT 1 FROM host_hostnames hh
                  WHERE hh.host_id = h.id AND hh.hostname ILIKE $5
              )
          )
        ORDER BY h.last_scanned_at DESC NULLS LAST, h.ip_addr ASC
        LIMIT $6 OFFSET $7
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(&status_filter)
    .bind(filter.is_unstable)
    .bind(filter.is_probable_tarpit)
    .bind(&search_pattern)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "hosts query failed", auth.request_id, instance))?;

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
    path = "/api/v1/hosts/{id}",
    tag = "Hosts",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Host UUID")),
    responses(
        (status = 200, description = "Full host inventory detail including ports, TLS, web observations, and availability samples", body = HostDetailDto),
        (status = 404, description = "Host not found", body = ProblemDetails)
    )
)]
pub async fn get_host(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<HostDetailDto>, AppError> {
    let instance = format!("/api/v1/hosts/{id}");
    auth.require(Permission::ViewInventoryAndDiffs, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;

    let host_row: Option<HostSummaryRow> = sqlx::query_as(
        r#"
        SELECT h.id, h.asset_group_id, ag.name AS asset_group_name, h.ip_addr,
               h.status, h.consecutive_misses, h.is_unstable, h.is_probable_tarpit,
               h.availability_profile, h.auto_tags, h.manual_tags, h.notes, h.owner_hint,
               h.tarpit_override_force_sv,
               (SELECT COUNT(*) FROM host_ports hp WHERE hp.host_id = h.id AND hp.state = 'active') AS open_port_count,
               h.first_seen_at, h.last_seen_at, h.last_scanned_at
        FROM hosts h
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE h.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(|err| map_db_err(err, "host lookup failed", auth.request_id, &instance))?;

    let Some(host_row) = host_row else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Host {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let host = host_row.into_dto(auth.request_id, &instance)?;

    let hostname_rows: Vec<HostnameRow> = sqlx::query_as(
        "SELECT id, hostname, source, first_seen_at, last_seen_at FROM host_hostnames WHERE host_id = $1 ORDER BY hostname ASC",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "hostnames lookup failed", auth.request_id, &instance))?;

    let hostnames = hostname_rows
        .into_iter()
        .map(|r| HostHostnameDto {
            id: r.id,
            hostname: r.hostname,
            source: r.source,
            first_seen_at: r.first_seen_at,
            last_seen_at: r.last_seen_at,
        })
        .collect();

    let port_rows: Vec<HostPortRow> = sqlx::query_as(
        r#"
        SELECT id, host_id, port, protocol, state, consecutive_misses,
               service_name, product, version, extra_info, is_web_candidate, tunnel,
               first_seen_at, last_seen_at
        FROM host_ports
        WHERE host_id = $1
        ORDER BY port ASC, protocol ASC
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "host ports lookup failed", auth.request_id, &instance))?;

    let port_ids: Vec<Uuid> = port_rows.iter().map(|p| p.id).collect();
    let mut tls_map: HashMap<Uuid, TlsCertificateDto> = HashMap::new();
    let mut web_map: HashMap<Uuid, Vec<WebObservationDto>> = HashMap::new();

    if !port_ids.is_empty() {
        let tls_rows: Vec<TlsCertRow> = sqlx::query_as(
            r#"
            SELECT host_port_id, sha256_fingerprint, subject_cn, issuer_cn, san_dns,
                   not_before, not_after, is_self_signed, observed_at
            FROM tls_certificates
            WHERE host_port_id = ANY($1)
            "#,
        )
        .bind(&port_ids)
        .fetch_all(pool)
        .await
        .map_err(|err| map_db_err(err, "tls lookup failed", auth.request_id, &instance))?;

        for row in tls_rows {
            tls_map.insert(
                row.host_port_id,
                TlsCertificateDto {
                    sha256_fingerprint: row.sha256_fingerprint,
                    subject_cn: row.subject_cn,
                    issuer_cn: row.issuer_cn,
                    san_dns: row.san_dns,
                    not_before: row.not_before,
                    not_after: row.not_after,
                    is_self_signed: row.is_self_signed,
                    observed_at: row.observed_at,
                },
            );
        }

        let web_rows: Vec<WebObsRow> = sqlx::query_as(
            r#"
            SELECT id, host_port_id, vhost, scheme, http_status, final_url, redirect_target,
                   title, headers_filtered, cookies_meta, favicon_mmh3, matched_technologies,
                   detected_paths, last_observed_at
            FROM web_observations
            WHERE host_port_id = ANY($1)
            ORDER BY vhost ASC, scheme ASC
            "#,
        )
        .bind(&port_ids)
        .fetch_all(pool)
        .await
        .map_err(|err| {
            map_db_err(
                err,
                "web observations lookup failed",
                auth.request_id,
                &instance,
            )
        })?;

        for row in web_rows {
            let cookies_meta: Vec<WebCookieMeta> =
                serde_json::from_value(row.cookies_meta).unwrap_or_default();
            let matched_technologies: Vec<String> =
                serde_json::from_value(row.matched_technologies).unwrap_or_default();
            web_map
                .entry(row.host_port_id)
                .or_default()
                .push(WebObservationDto {
                    id: row.id,
                    host_port_id: row.host_port_id,
                    vhost: row.vhost,
                    scheme: row.scheme,
                    http_status: row.http_status,
                    final_url: row.final_url,
                    redirect_target: row.redirect_target,
                    title: row.title,
                    headers_filtered: row.headers_filtered,
                    cookies_meta,
                    favicon_mmh3: row.favicon_mmh3,
                    matched_technologies,
                    detected_paths: row.detected_paths,
                    last_observed_at: row.last_observed_at,
                });
        }
    }

    let mut ports = Vec::with_capacity(port_rows.len());
    for p in port_rows {
        let state = PortState::from_db_str(&p.state).unwrap_or(PortState::Active);
        let tls_certificate = tls_map.remove(&p.id);
        let web_observations = web_map.remove(&p.id).unwrap_or_default();
        ports.push(HostPortDto {
            id: p.id,
            host_id: p.host_id,
            port: p.port,
            protocol: p.protocol,
            state,
            consecutive_misses: p.consecutive_misses,
            service_name: p.service_name,
            product: p.product,
            version: p.version,
            extra_info: p.extra_info,
            is_web_candidate: p.is_web_candidate,
            tunnel: p.tunnel,
            first_seen_at: p.first_seen_at,
            last_seen_at: p.last_seen_at,
            tls_certificate,
            web_observations,
        });
    }

    let sample_rows: Vec<SampleRow> = sqlx::query_as(
        r#"
        SELECT id, scan_run_id, time_slot, is_alive, open_ports_hash, sampled_at
        FROM host_availability_samples
        WHERE host_id = $1
        ORDER BY sampled_at DESC
        LIMIT 20
        "#,
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "availability samples lookup failed",
            auth.request_id,
            &instance,
        )
    })?;

    let availability_samples = sample_rows
        .into_iter()
        .filter_map(|s| {
            TimeSlot::from_db_str(&s.time_slot).map(|time_slot| HostAvailabilitySampleDto {
                id: s.id,
                scan_run_id: s.scan_run_id,
                time_slot,
                is_alive: s.is_alive,
                open_ports_hash: s.open_ports_hash,
                sampled_at: s.sampled_at,
            })
        })
        .collect();

    Ok(Json(HostDetailDto {
        host,
        hostnames,
        ports,
        availability_samples,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/hosts/{id}",
    tag = "Hosts",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Host UUID")),
    request_body = UpdateHostMetadataRequest,
    responses(
        (status = 200, description = "Updated analytical host metadata (Scan-First Truth safe)", body = HostSummaryDto),
        (status = 403, description = "Insufficient RBAC permission", body = ProblemDetails),
        (status = 404, description = "Host not found", body = ProblemDetails)
    )
)]
pub async fn update_host_metadata(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateHostMetadataRequest>,
) -> Result<Json<HostSummaryDto>, AppError> {
    let instance = format!("/api/v1/hosts/{id}");
    auth.require(Permission::EditAnalyticalMetadata, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let sanitized_tags = payload.manual_tags.map(|tags| {
        tags.into_iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
    });
    let sanitized_notes = payload.notes.map(|n| n.trim().to_string());
    let sanitized_owner = payload.owner_hint.map(|o| o.trim().to_string());

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, &instance))?;

    let updated_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE hosts
        SET manual_tags = COALESCE($1, manual_tags),
            notes = COALESCE($2, notes),
            owner_hint = COALESCE($3, owner_hint)
        WHERE id = $4
        RETURNING id
        "#,
    )
    .bind(&sanitized_tags)
    .bind(&sanitized_notes)
    .bind(&sanitized_owner)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "host metadata update failed",
            auth.request_id,
            &instance,
        )
    })?;

    if updated_id.is_none() {
        return Err(AppError::new(
            DomainError::NotFound(format!("Host {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    }

    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "host.metadata_updated",
            resource_type: "host",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "manual_tags": sanitized_tags,
                "owner_hint": sanitized_owner,
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

    let host_row: HostSummaryRow = sqlx::query_as(
        r#"
        SELECT h.id, h.asset_group_id, ag.name AS asset_group_name, h.ip_addr,
               h.status, h.consecutive_misses, h.is_unstable, h.is_probable_tarpit,
               h.availability_profile, h.auto_tags, h.manual_tags, h.notes, h.owner_hint,
               h.tarpit_override_force_sv,
               (SELECT COUNT(*) FROM host_ports hp WHERE hp.host_id = h.id AND hp.state = 'active') AS open_port_count,
               h.first_seen_at, h.last_seen_at, h.last_scanned_at
        FROM hosts h
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE h.id = $1
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "host reload failed", auth.request_id, &instance))?;

    Ok(Json(host_row.into_dto(auth.request_id, &instance)?))
}

#[utoipa::path(
    post,
    path = "/api/v1/hosts/{id}/tarpit-override",
    tag = "Hosts",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Host UUID")),
    request_body = TarpitOverrideRequest,
    responses(
        (status = 200, description = "Admin tarpit override flag updated", body = HostSummaryDto),
        (status = 403, description = "Admin permission ForceTarpitScan required", body = ProblemDetails),
        (status = 404, description = "Host not found", body = ProblemDetails)
    )
)]
pub async fn set_tarpit_override(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<TarpitOverrideRequest>,
) -> Result<Json<HostSummaryDto>, AppError> {
    let instance = format!("/api/v1/hosts/{id}/tarpit-override");
    auth.require(Permission::ForceTarpitScan, &instance)?;
    let pool = require_db(&state, auth.request_id, &instance)?;
    let source_ip = extract_source_ip(&headers);

    let mut tx = pool
        .begin()
        .await
        .map_err(|err| map_db_err(err, "tx begin failed", auth.request_id, &instance))?;

    let updated_ip: Option<IpNetwork> = sqlx::query_scalar(
        r#"
        UPDATE hosts
        SET tarpit_override_force_sv = $1,
            tarpit_override_by = CASE WHEN $1 THEN $2 ELSE NULL END,
            tarpit_override_at = CASE WHEN $1 THEN NOW() ELSE NULL END
        WHERE id = $3
        RETURNING ip_addr
        "#,
    )
    .bind(payload.force_sv)
    .bind(auth.user.id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        map_db_err(
            err,
            "tarpit override update failed",
            auth.request_id,
            &instance,
        )
    })?;

    let Some(ip_net) = updated_ip else {
        return Err(AppError::new(
            DomainError::NotFound(format!("Host {id} not found.")),
            auth.request_id,
            Some(instance),
        ));
    };

    let ip_addr: IpAddr = ip_net.ip();
    insert_audit_log(
        &mut *tx,
        AuditRecord {
            actor_type: "user",
            actor_id: Some(auth.user.id),
            action: "host.tarpit_override",
            resource_type: "host",
            resource_id: Some(id),
            before_state: None,
            after_state: Some(serde_json::json!({
                "ip_addr": ip_addr,
                "force_sv": payload.force_sv,
                "reason": payload.reason,
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

    let host_row: HostSummaryRow = sqlx::query_as(
        r#"
        SELECT h.id, h.asset_group_id, ag.name AS asset_group_name, h.ip_addr,
               h.status, h.consecutive_misses, h.is_unstable, h.is_probable_tarpit,
               h.availability_profile, h.auto_tags, h.manual_tags, h.notes, h.owner_hint,
               h.tarpit_override_force_sv,
               (SELECT COUNT(*) FROM host_ports hp WHERE hp.host_id = h.id AND hp.state = 'active') AS open_port_count,
               h.first_seen_at, h.last_seen_at, h.last_scanned_at
        FROM hosts h
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE h.id = $1
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "host reload failed", auth.request_id, &instance))?;

    Ok(Json(host_row.into_dto(auth.request_id, &instance)?))
}
