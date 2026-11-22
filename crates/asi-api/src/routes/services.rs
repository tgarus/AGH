use std::collections::BTreeMap;

use asi_common::error::DomainError;
use asi_common::inventory::{
    ClusterKind, ClusterMemberDto, DashboardStatsDto, PortState, ServiceClusterDto, ServiceRowDto,
};
use asi_common::pagination::{PaginatedResponse, PaginationMeta, PaginationQuery};
use asi_common::rbac::Permission;
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use sqlx::FromRow;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;
use crate::routes::common::{map_db_err, require_db};
use crate::security::auth_extractor::AuthenticatedUser;

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct ServiceFilterQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub asset_group_id: Option<Uuid>,
    pub q: Option<String>,
}

#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct ClusterFilterQuery {
    pub asset_group_id: Option<Uuid>,
    pub kind: Option<ClusterKind>,
    pub min_members: Option<usize>,
}

#[derive(FromRow)]
pub(crate) struct ServiceRow {
    host_id: Uuid,
    host_port_id: Uuid,
    asset_group_id: Uuid,
    asset_group_name: String,
    ip_addr: IpNetwork,
    port: i32,
    protocol: String,
    state: String,
    service_name: Option<String>,
    product: Option<String>,
    version: Option<String>,
    tunnel: Option<String>,
    vhost: Option<String>,
    scheme: Option<String>,
    http_status: Option<i32>,
    title: Option<String>,
    favicon_mmh3: Option<i64>,
    matched_technologies: Option<serde_json::Value>,
    detected_paths: Option<Vec<String>>,
    last_seen_at: DateTime<Utc>,
}

impl ServiceRow {
    pub(crate) fn into_dto(
        self,
        request_id: Option<Uuid>,
        instance: &str,
    ) -> Result<ServiceRowDto, AppError> {
        let state = PortState::from_db_str(&self.state).ok_or_else(|| {
            AppError::new(
                DomainError::Internal(format!("invalid port state '{}'", self.state)),
                request_id,
                Some(instance.to_string()),
            )
        })?;
        let matched_technologies = self
            .matched_technologies
            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
            .unwrap_or_default();
        Ok(ServiceRowDto {
            host_id: self.host_id,
            host_port_id: self.host_port_id,
            asset_group_id: self.asset_group_id,
            asset_group_name: self.asset_group_name,
            ip_addr: self.ip_addr.ip(),
            port: self.port,
            protocol: self.protocol,
            state,
            service_name: self.service_name,
            product: self.product,
            version: self.version,
            tunnel: self.tunnel,
            vhost: self.vhost,
            scheme: self.scheme,
            http_status: self.http_status,
            title: self.title,
            favicon_mmh3: self.favicon_mmh3,
            matched_technologies,
            detected_paths: self.detected_paths.unwrap_or_default(),
            last_seen_at: self.last_seen_at,
        })
    }
}

#[derive(FromRow)]
struct DashboardAggregateRow {
    total_hosts: i64,
    active_hosts: i64,
    unstable_hosts: i64,
    probable_tarpit_hosts: i64,
    active_ports: i64,
    web_observations: i64,
    unacknowledged_diffs: i64,
    confirmed_changes_24h: i64,
    active_variance_24h: i64,
    running_scans: i64,
    online_workers: i64,
    enabled_signatures: i64,
    enabled_notification_channels: i64,
}

#[must_use]
pub fn build_service_clusters(
    rows: &[ServiceRowDto],
    kind: ClusterKind,
    min_members: usize,
) -> Vec<ServiceClusterDto> {
    let threshold = min_members.max(2);
    let mut grouped: BTreeMap<String, (String, Vec<ClusterMemberDto>)> = BTreeMap::new();

    for row in rows {
        let member = ClusterMemberDto {
            host_id: row.host_id,
            asset_group_id: row.asset_group_id,
            asset_group_name: row.asset_group_name.clone(),
            ip_addr: row.ip_addr,
            port: row.port,
            vhost: row.vhost.clone(),
            scheme: row.scheme.clone(),
            http_status: row.http_status,
            title: row.title.clone(),
            favicon_mmh3: row.favicon_mmh3,
            matched_technologies: row.matched_technologies.clone(),
        };

        match kind {
            ClusterKind::Favicon => {
                if let Some(hash) = row.favicon_mmh3 {
                    let key = format!("favicon:{hash}");
                    let entry = grouped
                        .entry(key)
                        .or_insert_with(|| (format!("Favicon mmh3={hash}"), Vec::new()));
                    entry.1.push(member);
                }
            }
            ClusterKind::Title => {
                if let Some(raw_title) = row
                    .title
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let key = format!("title:{}", raw_title.to_ascii_lowercase());
                    let entry = grouped
                        .entry(key)
                        .or_insert_with(|| (raw_title.to_string(), Vec::new()));
                    entry.1.push(member);
                }
            }
            ClusterKind::Technology => {
                for tech in &row.matched_technologies {
                    let norm = tech.trim();
                    if norm.is_empty() {
                        continue;
                    }
                    let key = format!("tech:{}", norm.to_ascii_lowercase());
                    let entry = grouped
                        .entry(key)
                        .or_insert_with(|| (norm.to_string(), Vec::new()));
                    entry.1.push(member.clone());
                }
            }
        }
    }

    let mut clusters: Vec<ServiceClusterDto> = grouped
        .into_iter()
        .filter(|(_, (_, members))| members.len() >= threshold)
        .map(|(cluster_key, (label, members))| ServiceClusterDto {
            cluster_key,
            kind,
            label,
            member_count: members.len(),
            members,
        })
        .collect();

    clusters.sort_by(|a, b| {
        b.member_count
            .cmp(&a.member_count)
            .then_with(|| a.label.cmp(&b.label))
    });
    clusters
}

#[utoipa::path(
    get,
    path = "/api/v1/services",
    tag = "Services",
    security(("bearer_auth" = [])),
    params(ServiceFilterQuery),
    responses(
        (status = 200, description = "Paginated active services and web observations", body = PaginatedResponse<ServiceRowDto>)
    )
)]
pub async fn list_services(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<ServiceFilterQuery>,
) -> Result<Json<PaginatedResponse<ServiceRowDto>>, AppError> {
    let instance = "/api/v1/services";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let pg = PaginationQuery {
        page: filter.page,
        per_page: filter.per_page,
        ..Default::default()
    }
    .sanitized();

    let search = filter
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("%{s}%"));

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM host_ports hp
        INNER JOIN hosts h ON h.id = hp.host_id
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        LEFT JOIN web_observations wo ON wo.host_port_id = hp.id
        WHERE hp.state <> 'closed'
          AND ($1::uuid IS NULL OR h.asset_group_id = $1)
          AND (
              $2::text IS NULL
              OR h.ip_addr::text ILIKE $2
              OR COALESCE(hp.service_name, '') ILIKE $2
              OR COALESCE(hp.product, '') ILIKE $2
              OR COALESCE(wo.vhost, '') ILIKE $2
              OR COALESCE(wo.title, '') ILIKE $2
          )
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(&search)
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "services count failed", auth.request_id, instance))?;

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
          AND (
              $2::text IS NULL
              OR h.ip_addr::text ILIKE $2
              OR COALESCE(hp.service_name, '') ILIKE $2
              OR COALESCE(hp.product, '') ILIKE $2
              OR COALESCE(wo.vhost, '') ILIKE $2
              OR COALESCE(wo.title, '') ILIKE $2
          )
        ORDER BY h.ip_addr ASC, hp.port ASC, wo.vhost ASC NULLS LAST
        LIMIT $3 OFFSET $4
        "#,
    )
    .bind(filter.asset_group_id)
    .bind(&search)
    .bind(i64::from(pg.per_page))
    .bind(i64::try_from(pg.offset).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "services query failed", auth.request_id, instance))?;

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
    path = "/api/v1/clusters",
    tag = "Services",
    security(("bearer_auth" = [])),
    params(ClusterFilterQuery),
    responses(
        (status = 200, description = "Shadow IT service clusters grouped by favicon hash, title, or technology", body = Vec<ServiceClusterDto>)
    )
)]
pub async fn list_clusters(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
    Query(filter): Query<ClusterFilterQuery>,
) -> Result<Json<Vec<ServiceClusterDto>>, AppError> {
    let instance = "/api/v1/clusters";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let kind = filter.kind.unwrap_or(ClusterKind::Favicon);
    let min_members = filter.min_members.unwrap_or(2).max(2);

    let rows: Vec<ServiceRow> = sqlx::query_as(
        r#"
        SELECT h.id AS host_id, hp.id AS host_port_id, h.asset_group_id,
               ag.name AS asset_group_name, h.ip_addr, hp.port, hp.protocol, hp.state,
               hp.service_name, hp.product, hp.version, hp.tunnel,
               wo.vhost, wo.scheme, wo.http_status, wo.title, wo.favicon_mmh3,
               wo.matched_technologies, wo.detected_paths,
               wo.last_observed_at AS last_seen_at
        FROM web_observations wo
        INNER JOIN host_ports hp ON hp.id = wo.host_port_id
        INNER JOIN hosts h ON h.id = hp.host_id
        INNER JOIN asset_groups ag ON ag.id = h.asset_group_id
        WHERE hp.state <> 'closed'
          AND ($1::uuid IS NULL OR h.asset_group_id = $1)
        ORDER BY h.ip_addr ASC, hp.port ASC
        LIMIT 2000
        "#,
    )
    .bind(filter.asset_group_id)
    .fetch_all(pool)
    .await
    .map_err(|err| map_db_err(err, "clusters query failed", auth.request_id, instance))?;

    let dtos = rows
        .into_iter()
        .map(|r| r.into_dto(auth.request_id, instance))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Json(build_service_clusters(&dtos, kind, min_members)))
}

#[utoipa::path(
    get,
    path = "/api/v1/dashboard/summary",
    tag = "Dashboard",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Platform-wide KPI summary for the dashboard", body = DashboardStatsDto)
    )
)]
pub async fn dashboard_summary(
    auth: AuthenticatedUser,
    State(state): State<AppState>,
) -> Result<Json<DashboardStatsDto>, AppError> {
    let instance = "/api/v1/dashboard/summary";
    auth.require(Permission::ViewInventoryAndDiffs, instance)?;
    let pool = require_db(&state, auth.request_id, instance)?;

    let agg: DashboardAggregateRow = sqlx::query_as(
        r#"
        SELECT
            (SELECT COUNT(*) FROM hosts) AS total_hosts,
            (SELECT COUNT(*) FROM hosts WHERE status = 'active') AS active_hosts,
            (SELECT COUNT(*) FROM hosts WHERE is_unstable = TRUE) AS unstable_hosts,
            (SELECT COUNT(*) FROM hosts WHERE is_probable_tarpit = TRUE) AS probable_tarpit_hosts,
            (SELECT COUNT(*) FROM host_ports WHERE state = 'active') AS active_ports,
            (SELECT COUNT(*) FROM web_observations) AS web_observations,
            (SELECT COUNT(*) FROM diff_events WHERE acknowledged_at IS NULL) AS unacknowledged_diffs,
            (SELECT COUNT(*) FROM diff_events WHERE event_kind = 'confirmed_change' AND detected_at >= NOW() - INTERVAL '24 hours') AS confirmed_changes_24h,
            (SELECT COUNT(*) FROM diff_events WHERE event_kind = 'active_variance' AND detected_at >= NOW() - INTERVAL '24 hours') AS active_variance_24h,
            (SELECT COUNT(*) FROM scan_runs WHERE status IN ('queued', 'running', 'pausing')) AS running_scans,
            (SELECT COUNT(*) FROM worker_nodes WHERE status = 'online') AS online_workers,
            (SELECT COUNT(*) FROM signature_rules WHERE is_enabled = TRUE) AS enabled_signatures,
            (SELECT COUNT(*) FROM notification_channels WHERE is_enabled = TRUE) AS enabled_notification_channels
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|err| map_db_err(err, "dashboard summary query failed", auth.request_id, instance))?;

    Ok(Json(DashboardStatsDto {
        total_hosts: agg.total_hosts,
        active_hosts: agg.active_hosts,
        unstable_hosts: agg.unstable_hosts,
        probable_tarpit_hosts: agg.probable_tarpit_hosts,
        active_ports: agg.active_ports,
        web_observations: agg.web_observations,
        unacknowledged_diffs: agg.unacknowledged_diffs,
        confirmed_changes_24h: agg.confirmed_changes_24h,
        active_variance_24h: agg.active_variance_24h,
        running_scans: agg.running_scans,
        online_workers: agg.online_workers,
        enabled_signatures: agg.enabled_signatures,
        enabled_notification_channels: agg.enabled_notification_channels,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn sample_service(
        ip: &str,
        favicon: Option<i64>,
        title: Option<&str>,
        techs: &[&str],
    ) -> ServiceRowDto {
        ServiceRowDto {
            host_id: Uuid::new_v4(),
            host_port_id: Uuid::new_v4(),
            asset_group_id: Uuid::new_v4(),
            asset_group_name: "Lab".to_string(),
            ip_addr: ip.parse::<IpAddr>().unwrap(),
            port: 80,
            protocol: "tcp".to_string(),
            state: PortState::Active,
            service_name: Some("http".to_string()),
            product: None,
            version: None,
            tunnel: None,
            vhost: Some("app.lab.local".to_string()),
            scheme: Some("http".to_string()),
            http_status: Some(200),
            title: title.map(ToString::to_string),
            favicon_mmh3: favicon,
            matched_technologies: techs.iter().map(|s| (*s).to_string()).collect(),
            detected_paths: Vec::new(),
            last_seen_at: Utc::now(),
        }
    }

    #[test]
    fn clusters_services_by_favicon_title_and_technology() {
        let rows = vec![
            sample_service(
                "172.28.0.10",
                Some(-112233),
                Some("Jenkins"),
                &["Jenkins", "Nginx"],
            ),
            sample_service(
                "172.28.0.11",
                Some(-112233),
                Some("  jenkins "),
                &["Jenkins"],
            ),
            sample_service("172.28.0.12", Some(999), Some("Unique App"), &["Nginx"]),
        ];

        let by_fav = build_service_clusters(&rows, ClusterKind::Favicon, 2);
        assert_eq!(by_fav.len(), 1);
        assert_eq!(by_fav[0].member_count, 2);

        let by_title = build_service_clusters(&rows, ClusterKind::Title, 2);
        assert_eq!(by_title.len(), 1);
        assert_eq!(by_title[0].member_count, 2);

        let by_tech = build_service_clusters(&rows, ClusterKind::Technology, 2);
        assert_eq!(by_tech.len(), 2);
        assert_eq!(by_tech[0].member_count, 2);
    }
}
