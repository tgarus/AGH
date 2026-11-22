use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryTool {
    Naabu,
    Masscan,
}

impl DiscoveryTool {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Naabu => "naabu",
            Self::Masscan => "masscan",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "naabu" => Some(Self::Naabu),
            "masscan" => Some(Self::Masscan),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerCapabilities {
    pub naabu_version: Option<String>,
    pub masscan_version: Option<String>,
    pub nmap_version: Option<String>,
    pub nuclei_version: Option<String>,
    pub os_arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerRegisterRequest {
    pub name: String,
    pub segment_tag: Option<String>,
    pub max_concurrency: u32,
    pub capabilities: WorkerCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerRegisterResponse {
    pub worker_id: Uuid,
    pub registered_at: DateTime<Utc>,
    pub heartbeat_interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChunkLeaseRequest {
    pub worker_id: Uuid,
    pub max_chunks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChunkTarget {
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub vhosts: Vec<String>,
}

const fn default_inactivity_threshold() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySnapshot {
    pub port_spec: String,
    pub discovery_tool: DiscoveryTool,
    pub rate_pps: u32,
    pub per_ip_cooldown_ms: u64,
    pub subnet_concurrency: u32,
    pub kill_grace_seconds: u64,
    #[serde(default = "default_inactivity_threshold")]
    pub inactivity_threshold: u32,
    pub tarpit_port_threshold: u32,
    pub enable_nuclei: bool,
    #[schema(value_type = Vec<String>)]
    pub force_sv_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChunkLeaseResponse {
    pub chunk_id: Uuid,
    pub scan_run_id: Uuid,
    pub attempt_no: u32,
    pub targets: Vec<ChunkTarget>,
    pub excluded_cidrs: Vec<String>,
    pub policy: PolicySnapshot,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeartbeatRequest {
    pub worker_id: Uuid,
    pub attempt_no: u32,
    pub stage_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlDirective {
    Continue,
    GracefulStop,
    KillNow,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HeartbeatResponse {
    pub directive: ControlDirective,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerControlEvent {
    pub action: String,
    pub scan_run_id: Option<Uuid>,
    pub chunk_id: Option<Uuid>,
    pub grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Stage1PortFinding {
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Stage2ServiceFinding {
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub tunnel: Option<String>,
    pub is_web_candidate: bool,
    pub rdns_hostnames: Vec<String>,
    pub tls_sha256: Option<String>,
    pub tls_subject_cn: Option<String>,
    pub tls_issuer_cn: Option<String>,
    pub tls_san_dns: Vec<String>,
    pub tls_not_before: Option<DateTime<Utc>>,
    pub tls_not_after: Option<DateTime<Utc>>,
    pub tls_is_self_signed: Option<bool>,
}

/// Passive HTTP cookie metadata only. Raw cookie values are never stored or transmitted.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct WebCookieMeta {
    pub name: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Stage3WebObservation {
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub port: u16,
    pub vhost: String,
    pub scheme: String,
    pub http_status: Option<u16>,
    pub final_url: Option<String>,
    pub redirect_target: Option<String>,
    pub title: Option<String>,
    pub headers_filtered: HashMap<String, String>,
    pub cookies_meta: Vec<WebCookieMeta>,
    pub favicon_mmh3: Option<i64>,
    pub matched_technologies: Vec<String>,
    pub detected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChunkResultsSubmission {
    pub worker_id: Uuid,
    pub attempt_no: u32,
    pub duration_ms: u64,
    #[schema(value_type = Vec<String>)]
    pub probable_tarpit_ips: Vec<IpAddr>,
    pub stage1_ports: Vec<Stage1PortFinding>,
    pub stage2_services: Vec<Stage2ServiceFinding>,
    pub stage3_observations: Vec<Stage3WebObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChunkReleaseRequest {
    pub worker_id: Uuid,
    pub attempt_no: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ChunkResultsResponse {
    pub accepted: bool,
    pub scan_completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerSignaturesResponse {
    pub version_hash: String,
    pub yaml_rules: Vec<String>,
}
