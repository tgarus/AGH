use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::diff::{BulletItem, DiffEventKind, DiffSeverity, TimeSlot};
use crate::worker::WebCookieMeta;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    Active,
    MissingPending,
    Inactive,
    Ignored,
}

impl HostStatus {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::MissingPending => "missing_pending",
            Self::Inactive => "inactive",
            Self::Ignored => "ignored",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "missing_pending" => Some(Self::MissingPending),
            "inactive" => Some(Self::Inactive),
            "ignored" => Some(Self::Ignored),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Active,
    MissingPending,
    Closed,
}

impl PortState {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::MissingPending => "missing_pending",
            Self::Closed => "closed",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "missing_pending" => Some(Self::MissingPending),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostHostnameDto {
    pub id: Uuid,
    pub hostname: String,
    pub source: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TlsCertificateDto {
    pub sha256_fingerprint: String,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub san_dns: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub is_self_signed: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebObservationDto {
    pub id: Uuid,
    pub host_port_id: Uuid,
    pub vhost: String,
    pub scheme: String,
    pub http_status: Option<i32>,
    pub final_url: Option<String>,
    pub redirect_target: Option<String>,
    pub title: Option<String>,
    pub headers_filtered: serde_json::Value,
    pub cookies_meta: Vec<WebCookieMeta>,
    pub favicon_mmh3: Option<i64>,
    pub matched_technologies: Vec<String>,
    pub detected_paths: Vec<String>,
    pub last_observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostPortDto {
    pub id: Uuid,
    pub host_id: Uuid,
    pub port: i32,
    pub protocol: String,
    pub state: PortState,
    pub consecutive_misses: i32,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub is_web_candidate: bool,
    pub tunnel: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub tls_certificate: Option<TlsCertificateDto>,
    pub web_observations: Vec<WebObservationDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostAvailabilitySampleDto {
    pub id: Uuid,
    pub scan_run_id: Option<Uuid>,
    pub time_slot: TimeSlot,
    pub is_alive: bool,
    pub open_ports_hash: String,
    pub sampled_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostSummaryDto {
    pub id: Uuid,
    pub asset_group_id: Uuid,
    pub asset_group_name: String,
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub status: HostStatus,
    pub consecutive_misses: i32,
    pub is_unstable: bool,
    pub is_probable_tarpit: bool,
    pub availability_profile: serde_json::Value,
    pub auto_tags: Vec<String>,
    pub manual_tags: Vec<String>,
    pub notes: Option<String>,
    pub owner_hint: Option<String>,
    pub tarpit_override_force_sv: bool,
    pub open_port_count: i64,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_scanned_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostCommentDto {
    pub id: Uuid,
    pub host_id: Uuid,
    pub host_port_id: Option<Uuid>,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub author_id: Option<Uuid>,
    pub author_name: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateHostCommentRequest {
    #[serde(default)]
    pub host_port_id: Option<Uuid>,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostDetailDto {
    pub host: HostSummaryDto,
    pub hostnames: Vec<HostHostnameDto>,
    pub ports: Vec<HostPortDto>,
    pub availability_samples: Vec<HostAvailabilitySampleDto>,
    #[serde(default)]
    pub comments: Vec<HostCommentDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateHostMetadataRequest {
    pub manual_tags: Option<Vec<String>>,
    pub notes: Option<String>,
    pub owner_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TarpitOverrideRequest {
    pub force_sv: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiffEventDto {
    pub id: Uuid,
    pub host_id: Uuid,
    pub asset_group_id: Uuid,
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub scan_run_id: Option<Uuid>,
    pub event_kind: DiffEventKind,
    pub severity: DiffSeverity,
    pub bullet_items: Vec<BulletItem>,
    pub previous_snapshot: Option<serde_json::Value>,
    pub current_snapshot: Option<serde_json::Value>,
    pub acknowledged_by: Option<Uuid>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceRowDto {
    pub host_id: Uuid,
    pub host_port_id: Uuid,
    pub asset_group_id: Uuid,
    pub asset_group_name: String,
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub port: i32,
    pub protocol: String,
    pub state: PortState,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub tunnel: Option<String>,
    pub vhost: Option<String>,
    pub scheme: Option<String>,
    pub http_status: Option<i32>,
    pub title: Option<String>,
    pub favicon_mmh3: Option<i64>,
    pub matched_technologies: Vec<String>,
    pub detected_paths: Vec<String>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClusterKind {
    Favicon,
    Title,
    Technology,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClusterMemberDto {
    pub host_id: Uuid,
    pub asset_group_id: Uuid,
    pub asset_group_name: String,
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub port: i32,
    pub vhost: Option<String>,
    pub scheme: Option<String>,
    pub http_status: Option<i32>,
    pub title: Option<String>,
    pub favicon_mmh3: Option<i64>,
    pub matched_technologies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceClusterDto {
    pub cluster_key: String,
    pub kind: ClusterKind,
    pub label: String,
    pub member_count: usize,
    pub members: Vec<ClusterMemberDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardStatsDto {
    pub total_hosts: i64,
    pub active_hosts: i64,
    pub unstable_hosts: i64,
    pub probable_tarpit_hosts: i64,
    pub active_ports: i64,
    pub web_observations: i64,
    pub unacknowledged_diffs: i64,
    pub confirmed_changes_24h: i64,
    pub active_variance_24h: i64,
    pub running_scans: i64,
    pub online_workers: i64,
    pub enabled_signatures: i64,
    pub enabled_notification_channels: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanAnalyticsPointDto {
    pub scan_run_id: Uuid,
    pub asset_group_id: Uuid,
    pub asset_group_name: String,
    pub status: String,
    pub trigger_type: String,
    pub total_targets: i32,
    pub completed_chunks: i32,
    pub total_chunks: i32,
    pub duration_seconds: Option<i64>,
    pub ema_chunk_ms: Option<f64>,
    pub confirmed_diffs: i64,
    pub variance_diffs: i64,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PortCountDto {
    pub port: i32,
    pub protocol: String,
    pub service_name: Option<String>,
    pub host_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GroupInventoryStatDto {
    pub asset_group_id: Uuid,
    pub asset_group_name: String,
    pub active_hosts: i64,
    pub open_ports: i64,
    pub confirmed_diffs: i64,
    pub total_scans: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardAnalyticsDto {
    pub recent_scans: Vec<ScanAnalyticsPointDto>,
    pub top_open_ports: Vec<PortCountDto>,
    pub group_stats: Vec<GroupInventoryStatDto>,
    pub diffs_by_severity: std::collections::BTreeMap<String, i64>,
    pub diffs_by_kind: std::collections::BTreeMap<String, i64>,
}
