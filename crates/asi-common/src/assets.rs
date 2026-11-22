use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::rbac::Role;
use crate::worker::DiscoveryTool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Ip,
    Cidr,
    Domain,
    ExcludeCidr,
}

impl TargetType {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Domain => "domain",
            Self::ExcludeCidr => "exclude_cidr",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "ip" => Some(Self::Ip),
            "cidr" => Some(Self::Cidr),
            "domain" => Some(Self::Domain),
            "exclude_cidr" => Some(Self::ExcludeCidr),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IgnoredTargetType {
    Ip,
    Cidr,
    Domain,
}

impl IgnoredTargetType {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Domain => "domain",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "ip" => Some(Self::Ip),
            "cidr" => Some(Self::Cidr),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanPolicyDto {
    pub id: Uuid,
    pub name: String,
    pub port_spec: String,
    pub discovery_tool: DiscoveryTool,
    pub rate_pps: i32,
    pub per_ip_cooldown_ms: i32,
    pub subnet_concurrency: i32,
    pub kill_grace_seconds: i32,
    pub inactivity_threshold: i32,
    pub tarpit_port_threshold: i32,
    pub enable_nuclei: bool,
    pub time_windows: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateScanPolicyRequest {
    pub name: String,
    pub port_spec: String,
    pub discovery_tool: DiscoveryTool,
    pub rate_pps: i32,
    pub per_ip_cooldown_ms: i32,
    pub subnet_concurrency: i32,
    pub kill_grace_seconds: Option<i32>,
    pub inactivity_threshold: Option<i32>,
    pub tarpit_port_threshold: Option<i32>,
    pub enable_nuclei: Option<bool>,
    pub time_windows: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateScanPolicyRequest {
    pub name: Option<String>,
    pub port_spec: Option<String>,
    pub discovery_tool: Option<DiscoveryTool>,
    pub rate_pps: Option<i32>,
    pub per_ip_cooldown_ms: Option<i32>,
    pub subnet_concurrency: Option<i32>,
    pub kill_grace_seconds: Option<i32>,
    pub inactivity_threshold: Option<i32>,
    pub tarpit_port_threshold: Option<i32>,
    pub enable_nuclei: Option<bool>,
    pub time_windows: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssetGroupMemberDto {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub role: Role,
    pub assigned_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetAssetGroupMembersRequest {
    #[serde(default)]
    pub user_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssetGroupDto {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub policy_id: Uuid,
    pub schedule_cron: Option<String>,
    pub sampling_enabled: bool,
    pub external_refs: serde_json::Value,
    pub target_count: i64,
    #[serde(default)]
    pub assigned_user_ids: Vec<Uuid>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssetGroupTargetDto {
    pub id: Uuid,
    pub asset_group_id: Uuid,
    pub target_type: TargetType,
    pub value: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssetGroupDetailDto {
    pub group: AssetGroupDto,
    pub policy: ScanPolicyDto,
    pub targets: Vec<AssetGroupTargetDto>,
    #[serde(default)]
    pub members: Vec<AssetGroupMemberDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateAssetGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub policy_id: Uuid,
    pub schedule_cron: Option<String>,
    pub sampling_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateAssetGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub policy_id: Option<Uuid>,
    pub schedule_cron: Option<String>,
    pub sampling_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TargetInput {
    pub target_type: TargetType,
    pub value: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AddTargetsRequest {
    pub targets: Vec<TargetInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IgnoredTargetDto {
    pub id: Uuid,
    pub asset_group_id: Option<Uuid>,
    pub target_type: IgnoredTargetType,
    pub value: String,
    pub reason: String,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateIgnoredTargetRequest {
    pub asset_group_id: Option<Uuid>,
    pub target_type: IgnoredTargetType,
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkerNodeStatus {
    Online,
    Offline,
    Draining,
    Revoked,
}

impl WorkerNodeStatus {
    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "draining" => Some(Self::Draining),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

fn default_worker_visibility_scope() -> String {
    "all".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerNodeDto {
    pub id: Uuid,
    pub name: String,
    pub segment_tag: Option<String>,
    pub status: WorkerNodeStatus,
    pub capabilities: serde_json::Value,
    pub max_concurrency: i32,
    #[serde(default = "default_worker_visibility_scope")]
    pub visibility_scope: String,
    #[serde(default)]
    pub allowed_asset_group_ids: Vec<Uuid>,
    #[serde(default)]
    pub allowed_user_ids: Vec<Uuid>,
    #[serde(default)]
    pub created_by: Option<Uuid>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub registered_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateWorkerTokenRequest {
    pub name: String,
    pub segment_tag: Option<String>,
    pub max_concurrency: Option<i32>,
    #[serde(default)]
    pub visibility_scope: Option<String>,
    #[serde(default)]
    pub allowed_asset_group_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub allowed_user_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateWorkerTokenResponse {
    pub worker: WorkerNodeDto,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLogDto {
    pub id: Uuid,
    pub actor_type: String,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<Uuid>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub source_ip: Option<String>,
    pub request_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
