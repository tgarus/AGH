use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::diff::{BulletItem, DiffEventKind, DiffSeverity};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanProgressEvent {
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub scan_run_id: Uuid,
    pub completed_chunks: u32,
    pub total_chunks: u32,
    pub percent: f32,
    pub ema_chunk_ms: Option<f64>,
    pub eta_seconds: Option<u64>,
    pub estimated_finish_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScanStatusChangedEvent {
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub scan_run_id: Uuid,
    pub previous_status: String,
    pub current_status: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiffDetectedEvent {
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub diff_event_id: Uuid,
    pub host_id: Uuid,
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub event_kind: DiffEventKind,
    pub severity: DiffSeverity,
    pub bullet_items: Vec<BulletItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostAnomalyType {
    ProbableTarpit,
    Unstable,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HostAnomalyEvent {
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub host_id: Uuid,
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub anomaly_type: HostAnomalyType,
    pub open_port_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkerStatusEvent {
    pub event_id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub worker_id: Uuid,
    pub name: String,
    pub status: String,
    pub active_chunks: u32,
}
