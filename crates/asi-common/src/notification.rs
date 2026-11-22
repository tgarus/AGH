use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::diff::{BulletItem, DiffEventKind, DiffSeverity};
use crate::error::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannelType {
    WebhookJson,
    Slack,
    Teams,
    Mattermost,
    Smtp,
}

impl NotificationChannelType {
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::WebhookJson => "webhook_json",
            Self::Slack => "slack",
            Self::Teams => "teams",
            Self::Mattermost => "mattermost",
            Self::Smtp => "smtp",
        }
    }

    #[must_use]
    pub fn from_db_str(raw: &str) -> Option<Self> {
        match raw {
            "webhook_json" => Some(Self::WebhookJson),
            "slack" => Some(Self::Slack),
            "teams" => Some(Self::Teams),
            "mattermost" => Some(Self::Mattermost),
            "smtp" => Some(Self::Smtp),
            _ => None,
        }
    }
}

pub const WEBHOOK_EVENT_TYPES: &[&str] = &[
    "diff.confirmed_change",
    "diff.active_variance",
    "scan.started",
    "scan.completed",
    "host.new_discovered",
    "host.admin_panel_detected",
    "host.anomaly_detected",
    "defectdojo.finding_pushed",
];

#[must_use]
pub fn default_subscribed_events() -> Vec<String> {
    vec![
        "diff.confirmed_change".to_string(),
        "diff.active_variance".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NotificationChannelDto {
    pub id: Uuid,
    pub name: String,
    pub channel_type: NotificationChannelType,
    pub asset_group_id: Option<Uuid>,
    pub notify_on_confirmed: bool,
    pub notify_on_variance: bool,
    #[serde(default = "default_subscribed_events")]
    pub subscribed_events: Vec<String>,
    pub config_public: serde_json::Value,
    pub has_secret: bool,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateNotificationChannelRequest {
    pub name: String,
    pub channel_type: NotificationChannelType,
    pub asset_group_id: Option<Uuid>,
    pub notify_on_confirmed: Option<bool>,
    pub notify_on_variance: Option<bool>,
    #[serde(default)]
    pub subscribed_events: Option<Vec<String>>,
    pub config_public: serde_json::Value,
    pub secret: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateNotificationChannelRequest {
    pub name: Option<String>,
    pub notify_on_confirmed: Option<bool>,
    pub notify_on_variance: Option<bool>,
    #[serde(default)]
    pub subscribed_events: Option<Vec<String>>,
    pub config_public: Option<serde_json::Value>,
    pub secret: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NotificationDeliveryDto {
    pub id: Uuid,
    pub channel_id: Uuid,
    pub channel_name: String,
    pub diff_event_id: Option<Uuid>,
    pub event_type: String,
    pub custom_payload: Option<serde_json::Value>,
    pub status: String,
    pub attempt_count: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub sent_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TriggerCustomWebhookRequest {
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TestNotificationResponse {
    pub delivered: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NotificationMessage {
    pub delivery_id: Uuid,
    pub diff_event_id: Uuid,
    pub asset_group_name: String,
    pub host_id: Uuid,
    #[schema(value_type = String)]
    pub ip_addr: IpAddr,
    pub event_kind: DiffEventKind,
    pub severity: DiffSeverity,
    pub bullet_items: Vec<BulletItem>,
    pub detected_at: DateTime<Utc>,
}

#[async_trait]
pub trait NotificationSink: Send + Sync {
    async fn send(&self, message: &NotificationMessage) -> Result<(), DomainError>;

    async fn send_custom_event(
        &self,
        _event_type: &str,
        _delivery_id: Uuid,
        _payload: &serde_json::Value,
    ) -> Result<(), DomainError> {
        Err(DomainError::BadRequest(
            "Custom webhook event delivery is not supported for this sink.".to_string(),
        ))
    }
}
