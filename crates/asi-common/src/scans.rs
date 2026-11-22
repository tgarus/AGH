use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::diff::TimeSlot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanTriggerType {
    Manual,
    Scheduled,
    Sampling,
}

impl ScanTriggerType {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Scheduled => "scheduled",
            Self::Sampling => "sampling",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "manual" => Some(Self::Manual),
            "scheduled" => Some(Self::Scheduled),
            "sampling" => Some(Self::Sampling),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanRunStatus {
    Queued,
    Running,
    Pausing,
    Paused,
    Stopping,
    Stopped,
    Completed,
    Failed,
}

impl ScanRunStatus {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Pausing => "pausing",
            Self::Paused => "paused",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "pausing" => Some(Self::Pausing),
            "paused" => Some(Self::Paused),
            "stopping" => Some(Self::Stopping),
            "stopped" => Some(Self::Stopped),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    Pending,
    Leased,
    Completed,
    Failed,
    Cancelled,
}

impl ChunkStatus {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "pending" => Some(Self::Pending),
            "leased" => Some(Self::Leased),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PreflightRequest {
    pub asset_group_id: Uuid,
    pub window_minutes: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PreflightResponse {
    pub asset_group_id: Uuid,
    pub total_targets: u32,
    pub total_chunks: u32,
    pub chunk_size: u32,
    pub estimated_ports_per_host: u32,
    pub estimated_duration_seconds: u64,
    pub fits_in_window: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StartScanRequest {
    pub asset_group_id: Uuid,
    pub trigger_type: Option<ScanTriggerType>,
    pub time_slot: Option<TimeSlot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanRunDto {
    pub id: Uuid,
    pub asset_group_id: Uuid,
    pub policy_snapshot: serde_json::Value,
    pub trigger_type: ScanTriggerType,
    pub time_slot: Option<TimeSlot>,
    pub status: ScanRunStatus,
    pub total_targets: i32,
    pub total_chunks: i32,
    pub completed_chunks: i32,
    pub ema_chunk_ms: Option<f64>,
    pub estimated_finish_at: Option<DateTime<Utc>>,
    pub started_by: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanChunkDto {
    pub id: Uuid,
    pub scan_run_id: Uuid,
    pub sequence_no: i32,
    pub subnet_bucket: String,
    pub targets: serde_json::Value,
    pub status: ChunkStatus,
    pub attempt_no: i32,
    pub leased_by_worker_id: Option<Uuid>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
